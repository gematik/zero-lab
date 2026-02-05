package pkcs12

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrDecryption      = errors.New("pkcs12: decryption failed")
	ErrAuthentication  = errors.New("pkcs12: MAC verification failed")
	ErrInvalidPadding  = errors.New("pkcs12: invalid padding")
)

// DecryptPBES2 decrypts data encrypted with PBES2 scheme
func DecryptPBES2(encAlg *EncryptionAlgorithm, password []byte, data []byte) ([]byte, error) {
	if encAlg.KDF == nil || encAlg.Cipher == nil {
		return nil, fmt.Errorf("%w: invalid PBES2 parameters", ErrDecryption)
	}
	
	// Derive key using PBKDF2
	keyLen := getKeyLength(encAlg.Cipher.Algorithm)
	if keyLen == 0 {
		return nil, fmt.Errorf("%w: unsupported cipher algorithm", ErrUnsupportedAlgorithm)
	}
	
	prfFunc := getPRFFunc(encAlg.KDF.PRF)
	if prfFunc == nil {
		return nil, fmt.Errorf("%w: unsupported PRF algorithm", ErrUnsupportedAlgorithm)
	}
	
	key := pbkdf2.Key(password, encAlg.KDF.Salt, encAlg.KDF.Iterations, keyLen, prfFunc)
	
	// Decrypt based on cipher algorithm
	switch {
	case encAlg.Cipher.Algorithm.Equal(OIDAes128CBC):
		return decryptAESCBC(key, encAlg.Cipher.IV, data)
	case encAlg.Cipher.Algorithm.Equal(OIDAes192CBC):
		return decryptAESCBC(key, encAlg.Cipher.IV, data)
	case encAlg.Cipher.Algorithm.Equal(OIDAes256CBC):
		return decryptAESCBC(key, encAlg.Cipher.IV, data)
	default:
		return nil, fmt.Errorf("%w: cipher %v", ErrUnsupportedAlgorithm, encAlg.Cipher.Algorithm)
	}
}

// DecryptLegacyPBE decrypts data encrypted with legacy PKCS#12 PBE schemes
func DecryptLegacyPBE(encAlg *EncryptionAlgorithm, password []byte, data []byte) ([]byte, error) {
	if encAlg.Algorithm.Equal(OIDPBEWithSHAAnd3KeyTripleDESCBC) {
		return decryptPBEWithSHAAnd3KeyTripleDES(password, encAlg.Salt, encAlg.Iterations, data)
	}
	
	return nil, fmt.Errorf("%w: legacy algorithm %v", ErrUnsupportedAlgorithm, encAlg.Algorithm)
}

// DecryptEncryptedData decrypts a PKCS#7 EncryptedData ContentInfo
func DecryptEncryptedData(contentInfo ContentInfo, password []byte) ([]byte, error) {
	if !contentInfo.ContentType.Equal(OIDEncryptedData) {
		return nil, fmt.Errorf("%w: not encrypted data", ErrDecryption)
	}
	
	// Parse EncryptedData structure
	var encData encryptedData
	if _, err := asn1.Unmarshal(contentInfo.Content, &encData); err != nil {
		return nil, fmt.Errorf("%w: failed to parse EncryptedData: %v", ErrDecryption, err)
	}
	
	if encData.Version != 0 {
		return nil, fmt.Errorf("%w: unsupported EncryptedData version %d", ErrDecryption, encData.Version)
	}
	
	// Parse encryption algorithm
	encAlg, err := ParseEncryptionAlgorithm(encData.EncryptedContentInfo.ContentEncryptionAlgorithm)
	if err != nil {
		return nil, err
	}
	
	// Decrypt based on algorithm
	var plaintext []byte
	if encAlg.Algorithm.Equal(OIDPBES2) {
		plaintext, err = DecryptPBES2(encAlg, password, encData.EncryptedContentInfo.EncryptedContent)
	} else {
		plaintext, err = DecryptLegacyPBE(encAlg, password, encData.EncryptedContentInfo.EncryptedContent)
	}
	
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// DecryptShroudedKeyBag decrypts a PKCS8ShroudedKeyBag
func DecryptShroudedKeyBag(bagValue []byte, password []byte) ([]byte, error) {
	epki, err := ParseEncryptedPrivateKeyInfo(bagValue)
	if err != nil {
		return nil, err
	}
	
	encAlg, err := ParseEncryptionAlgorithm(epki.Algorithm)
	if err != nil {
		return nil, err
	}
	
	var plaintext []byte
	if encAlg.Algorithm.Equal(OIDPBES2) {
		plaintext, err = DecryptPBES2(encAlg, password, epki.Data)
	} else {
		plaintext, err = DecryptLegacyPBE(encAlg, password, epki.Data)
	}
	
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// VerifyMAC verifies the MAC on a PKCS#12 file
func VerifyMAC(pfx *PFX, password []byte) error {
	if pfx.MacData == nil {
		// No MAC to verify
		return nil
	}
	
	// Derive MAC key using PKCS#12 key derivation
	macKey, err := deriveMACKey(pfx.MacData.Mac.Algorithm.Algorithm, password, 
		pfx.MacData.MacSalt, pfx.MacData.Iterations)
	if err != nil {
		return err
	}
	
	// Compute MAC over authenticated safe
	hashFunc := getHashFunc(pfx.MacData.Mac.Algorithm.Algorithm)
	if hashFunc == nil {
		return fmt.Errorf("%w: unsupported MAC algorithm %v", 
			ErrUnsupportedAlgorithm, pfx.MacData.Mac.Algorithm.Algorithm)
	}
	
	mac := hmac.New(hashFunc, macKey)
	mac.Write(pfx.RawAuthSafe)
	expectedMAC := mac.Sum(nil)
	
	if !hmac.Equal(expectedMAC, pfx.MacData.Mac.Digest) {
		return ErrAuthentication
	}
	
	return nil
}

// Helper: decryptAESCBC decrypts data using AES-CBC
func decryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create AES cipher: %v", ErrDecryption, err)
	}
	
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext not multiple of block size", ErrDecryption)
	}
	
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("%w: invalid IV length", ErrDecryption)
	}
	
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	
	// Remove PKCS#7 padding
	plaintext, err = removePKCS7Padding(plaintext)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// Helper: decryptPBEWithSHAAnd3KeyTripleDES decrypts using legacy 3DES
func decryptPBEWithSHAAnd3KeyTripleDES(password, salt []byte, iterations int, ciphertext []byte) ([]byte, error) {
	// Derive key and IV using PKCS#12 KDF with SHA-1
	sha1Hash := func(b []byte) []byte { h := sha1.Sum(b); return h[:] }
	key := derivePKCS12Key(sha1Hash, 20, 64, password, salt, iterations, 1, 24) // 24 bytes for 3DES
	iv := derivePKCS12Key(sha1Hash, 20, 64, password, salt, iterations, 2, 8)   // 8 bytes IV
	
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create 3DES cipher: %v", ErrDecryption, err)
	}
	
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("%w: ciphertext not multiple of block size", ErrDecryption)
	}
	
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	
	// Remove PKCS#7 padding
	plaintext, err = removePKCS7Padding(plaintext)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// Helper: removePKCS7Padding removes PKCS#7 padding from plaintext
func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrInvalidPadding
	}
	
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) {
		return nil, ErrInvalidPadding
	}
	
	// Verify padding
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, ErrInvalidPadding
		}
	}
	
	return data[:len(data)-padLen], nil
}

// Helper: derivePKCS12Key derives key material using PKCS#12 KDF (RFC 7292 Appendix B)
// Reference implementation from golang.org/x/crypto/pkcs12
// id: 1 for encryption key, 2 for IV, 3 for MAC key
// hash: the hash function to use (sha1, sha256, sha512, etc.)
func derivePKCS12Key(hash func([]byte) []byte, u, v int, password, salt []byte, iterations, id, keyLen int) []byte {
	// Convert password to UTF-16BE with null terminator (PKCS#12 requirement)
	passwordBMP := encodePasswordPKCS12(password)
	
	// Step 1: Construct diversifier D
	D := make([]byte, v)
	for i := range D {
		D[i] = byte(id)
	}
	
	// Step 2: Create S by repeating salt
	S := fillWithRepeats(salt, v)
	
	// Step 3: Create P by repeating password
	P := fillWithRepeats(passwordBMP, v)
	
	// Step 4: Set I = S || P
	I := append(S, P...)
	
	// Step 5: Set c = ceiling(keyLen/u)
	c := (keyLen + u - 1) / u
	
	// Step 6: Iterate c times
	A := make([]byte, c*u)
	
	for i := 0; i < c; i++ {
		// Step 6a: Compute H^iterations(D || I)
		Ai := hash(append(D, I...))
		
		for j := 1; j < iterations; j++ {
			Ai = hash(Ai)
		}
		
		copy(A[i*u:], Ai)
		
		if i < c-1 { // Not last iteration
			// Step 6b: Create B by repeating Ai
			B := fillWithRepeats(Ai, v)
			
			// Step 6c: Update I by adding B+1 to each block
			// Using big integer arithmetic for correctness
			Bbi := new(big.Int).SetBytes(B)
			Ij := new(big.Int)
			one := big.NewInt(1)
			
			for j := 0; j < len(I)/v; j++ {
				Ij.SetBytes(I[j*v : (j+1)*v])
				Ij.Add(Ij, Bbi)
				Ij.Add(Ij, one)
				
				Ijb := Ij.Bytes()
				
				// Pad or truncate to v bytes
				if len(Ijb) > v {
					Ijb = Ijb[len(Ijb)-v:]
				}
				if len(Ijb) < v {
					padded := make([]byte, v)
					copy(padded[v-len(Ijb):], Ijb)
					Ijb = padded
				}
				
				copy(I[j*v:], Ijb)
			}
		}
	}
	
	return A[:keyLen]
}

// Helper: fillWithRepeats creates a byte slice by repeating pattern
func fillWithRepeats(pattern []byte, v int) []byte {
	if len(pattern) == 0 {
		return nil
	}
	
	outputLen := v * ((len(pattern) + v - 1) / v)
	result := make([]byte, outputLen)
	
	for i := 0; i < outputLen; i++ {
		result[i] = pattern[i%len(pattern)]
	}
	
	return result
}

// Helper: deriveMACKey derives MAC key using PKCS#12 KDF
func deriveMACKey(macAlg asn1.ObjectIdentifier, password, salt []byte, iterations int) ([]byte, error) {
	var hash func([]byte) []byte
	var u, v, keyLen int
	
	switch {
	case macAlg.Equal(OIDSHA1):
		hash = func(b []byte) []byte { h := sha1.Sum(b); return h[:] }
		u, v, keyLen = 20, 64, 20
	case macAlg.Equal(OIDSHA256) || macAlg.Equal(OIDHMACSHA256):
		hash = func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }
		u, v, keyLen = 32, 64, 32
	case macAlg.Equal(OIDSHA384) || macAlg.Equal(OIDHMACSHA384):
		hash = func(b []byte) []byte { h := sha512.Sum384(b); return h[:] }
		u, v, keyLen = 48, 128, 48
	case macAlg.Equal(OIDSHA512) || macAlg.Equal(OIDHMACSHA512):
		hash = func(b []byte) []byte { h := sha512.Sum512(b); return h[:] }
		u, v, keyLen = 64, 128, 64
	default:
		return nil, fmt.Errorf("%w: unsupported MAC algorithm %v", ErrUnsupportedAlgorithm, macAlg)
	}
	
	// Use PKCS#12 KDF with id=3 for MAC
	key := derivePKCS12Key(hash, u, v, password, salt, iterations, 3, keyLen)
	return key, nil
}

// Helper: encodePasswordPKCS12 encodes password as BMPString (UTF-16BE) with null terminator
// Reference implementation from golang.org/x/crypto/pkcs12/bmp-string.go
func encodePasswordPKCS12(password []byte) []byte {
	if len(password) == 0 {
		return []byte{0, 0} // Just null terminator for empty password
	}
	
	// Convert to UTF-16BE (UCS-2) with null terminator
	s := string(password)
	ret := make([]byte, 0, 2*len(s)+2)
	
	for _, r := range s {
		ret = append(ret, byte(r/256), byte(r%256))
	}
	ret = append(ret, 0, 0) // Null terminator
	
	return ret
}

// Helper: getKeyLength returns key length for cipher algorithm
func getKeyLength(cipher asn1.ObjectIdentifier) int {
	switch {
	case cipher.Equal(OIDAes128CBC):
		return 16
	case cipher.Equal(OIDAes192CBC):
		return 24
	case cipher.Equal(OIDAes256CBC):
		return 32
	default:
		return 0
	}
}

// Helper: getPRFFunc returns hash function for PRF
func getPRFFunc(prf asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case prf.Equal(OIDHMACSHA1):
		return sha1.New
	case prf.Equal(OIDHMACSHA256) || prf.Equal(OIDSHA256):
		return sha256.New
	case prf.Equal(OIDHMACSHA384) || prf.Equal(OIDSHA384):
		return sha512.New384
	case prf.Equal(OIDHMACSHA512) || prf.Equal(OIDSHA512):
		return sha512.New
	default:
		return sha1.New // Default to SHA-1 for compatibility
	}
}

// Helper: getHashFunc returns hash function for MAC algorithm
func getHashFunc(macAlg asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case macAlg.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}): // SHA-1
		return sha1.New
	case macAlg.Equal(OIDSHA256) || macAlg.Equal(OIDHMACSHA256):
		return sha256.New
	case macAlg.Equal(OIDSHA384) || macAlg.Equal(OIDHMACSHA384):
		return sha512.New384
	case macAlg.Equal(OIDSHA512) || macAlg.Equal(OIDHMACSHA512):
		return sha512.New
	default:
		return nil
	}
}

// encryptedData represents PKCS#7 EncryptedData
type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

// encryptedContentInfo represents the encrypted content
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}
