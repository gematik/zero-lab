package pkcs12

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// EncodeOptions configures PKCS#12 encoding
type EncodeOptions struct {
	// Encryption algorithm for private keys (default: AES-256-CBC)
	KeyEncryption asn1.ObjectIdentifier
	
	// Encryption algorithm for certificates (default: AES-256-CBC)
	CertEncryption asn1.ObjectIdentifier
	
	// Number of iterations for PBKDF2 (default: 2048)
	Iterations int
	
	// MAC algorithm (default: SHA-256)
	MacAlgorithm asn1.ObjectIdentifier
	
	// Separate encryption passwords for keys and certificates
	// If nil, uses main password for both
	KeyPassword  []byte
	CertPassword []byte
	
	// Include MAC for integrity verification (default: true)
	IncludeMAC bool
	
	// Internal: last used salt and IV (for algorithm identifier)
	lastSalt []byte
	lastIV   []byte
}

// DefaultEncodeOptions returns secure default encoding options
func DefaultEncodeOptions() *EncodeOptions {
	return &EncodeOptions{
		KeyEncryption:  OIDAes256CBC,
		CertEncryption: OIDAes256CBC,
		Iterations:     2048,
		MacAlgorithm:   OIDSHA256,
		IncludeMAC:     true,
	}
}

// Encode creates a PKCS#12 file from bags with default options.
// For more control, use EncodeWithOptions.
//
// Example:
//
//	p12Data, err := pkcs12.Encode(bags, []byte("password"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	os.WriteFile("keystore.p12", p12Data, 0600)
func Encode(bags *Bags, password []byte) ([]byte, error) {
	return EncodeWithOptions(bags, password, DefaultEncodeOptions())
}

// EncodeWithOptions creates a PKCS#12 file from bags with custom options
func EncodeWithOptions(bags *Bags, password []byte, opts *EncodeOptions) ([]byte, error) {
	if opts == nil {
		opts = DefaultEncodeOptions()
	}
	
	// Set password defaults
	if opts.KeyPassword == nil {
		opts.KeyPassword = password
	}
	if opts.CertPassword == nil {
		opts.CertPassword = password
	}
	
	// Create two SafeContents:
	// 1. Keys (encrypted)
	// 2. Certificates (encrypted or unencrypted)
	
	var contentInfos []ContentInfo
	
	// Add encrypted private keys
	if len(bags.PrivateKeys) > 0 {
		keySafeBags := make([]SafeBag, 0, len(bags.PrivateKeys))
		for _, key := range bags.PrivateKeys {
			bag, err := createShroudedKeyBag(key, opts.KeyPassword, opts)
			if err != nil {
				return nil, fmt.Errorf("failed to create key bag: %w", err)
			}
			keySafeBags = append(keySafeBags, bag)
		}
		
		// Serialize SafeContents
		safeContents := SafeContents{Bags: keySafeBags}
		safeData, err := serializeSafeContents(&safeContents)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key safe contents: %w", err)
		}
		
		// Create encrypted ContentInfo
		ci, err := createEncryptedContentInfo(safeData, opts.CertPassword, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create encrypted content: %w", err)
		}
		contentInfos = append(contentInfos, ci)
	}
	
	// Add certificates (unencrypted for compatibility)
	if len(bags.Certificates) > 0 {
		certSafeBags := make([]SafeBag, 0, len(bags.Certificates))
		for _, cert := range bags.Certificates {
			bag, err := createCertBag(cert)
			if err != nil {
				return nil, fmt.Errorf("failed to create cert bag: %w", err)
			}
			certSafeBags = append(certSafeBags, bag)
		}
		
		// Serialize SafeContents
		safeContents := SafeContents{Bags: certSafeBags}
		safeData, err := serializeSafeContents(&safeContents)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize cert safe contents: %w", err)
		}
		
		// Create unencrypted Data ContentInfo
		ci, err := createDataContentInfo(safeData)
		if err != nil {
			return nil, fmt.Errorf("failed to create data content: %w", err)
		}
		contentInfos = append(contentInfos, ci)
	}
	
	// Create AuthenticatedSafe
	authSafe := AuthenticatedSafe{ContentInfos: contentInfos}
	authSafeData, err := serializeAuthenticatedSafe(&authSafe)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize authenticated safe: %w", err)
	}
	
	// Wrap in Data ContentInfo
	authSafeCI, err := createDataContentInfo(authSafeData)
	if err != nil {
		return nil, fmt.Errorf("failed to create authsafe content: %w", err)
	}
	
	// Create PFX
	pfx := PFX{
		Version:     3,
		AuthSafe:    authSafeCI,
		RawAuthSafe: authSafeData,
	}
	
	// Generate MAC if requested
	if opts.IncludeMAC {
		macData, err := generateMAC(authSafeData, password, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to generate MAC: %w", err)
		}
		pfx.MacData = macData
	}
	
	// Serialize PFX
	return serializePFX(&pfx)
}

// createShroudedKeyBag creates an encrypted PKCS8ShroudedKeyBag
func createShroudedKeyBag(key PrivateKeyBag, password []byte, opts *EncodeOptions) (SafeBag, error) {
	// Encrypt the private key
	encrypted, err := encryptPrivateKey(key.Raw, password, opts)
	if err != nil {
		return SafeBag{}, err
	}
	
	// Build algorithm identifier for PBES2
	algorithm, err := buildPBES2AlgorithmIdentifier(opts)
	if err != nil {
		return SafeBag{}, err
	}
	
	// Create EncryptedPrivateKeyInfo
	epki := EncryptedPrivateKeyInfo{
		Algorithm: algorithm,
		Data:      encrypted,
	}
	
	// Serialize EPKI
	epkiData, err := asn1.Marshal(epki)
	if err != nil {
		return SafeBag{}, fmt.Errorf("failed to marshal EPKI: %w", err)
	}
	
	// Create attributes
	var attrs []PKCS12Attribute
	if key.FriendlyName != "" {
		attr, err := createFriendlyNameAttribute(key.FriendlyName)
		if err == nil {
			attrs = append(attrs, attr)
		}
	}
	if len(key.LocalKeyID) > 0 {
		attr, err := createLocalKeyIDAttribute(key.LocalKeyID)
		if err == nil {
			attrs = append(attrs, attr)
		}
	}
	
	return SafeBag{
		BagID:      OIDPKCS8ShroudedKeyBag,
		BagValue:   epkiData,
		Attributes: attrs,
	}, nil
}

// createCertBag creates a CertBag
func createCertBag(cert CertificateBag) (SafeBag, error) {
	// Create CertBag structure
	certBag := struct {
		CertID    asn1.ObjectIdentifier
		CertValue asn1.RawValue `asn1:"tag:0,explicit"`
	}{
		CertID: OIDX509Certificate,
		CertValue: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      cert.Raw,
		},
	}
	
	// Marshal to get the explicit tag wrapper
	innerOctet, err := asn1.Marshal(cert.Raw)
	if err != nil {
		return SafeBag{}, err
	}
	
	certBag.CertValue.Bytes = innerOctet
	
	// Serialize CertBag
	certBagData, err := asn1.Marshal(certBag)
	if err != nil {
		return SafeBag{}, fmt.Errorf("failed to marshal cert bag: %w", err)
	}
	
	// Create attributes
	var attrs []PKCS12Attribute
	if cert.FriendlyName != "" {
		attr, err := createFriendlyNameAttribute(cert.FriendlyName)
		if err == nil {
			attrs = append(attrs, attr)
		}
	}
	if len(cert.LocalKeyID) > 0 {
		attr, err := createLocalKeyIDAttribute(cert.LocalKeyID)
		if err == nil {
			attrs = append(attrs, attr)
		}
	}
	
	return SafeBag{
		BagID:      OIDCertBag,
		BagValue:   certBagData,
		Attributes: attrs,
	}, nil
}

// createFriendlyNameAttribute creates a friendlyName attribute
func createFriendlyNameAttribute(name string) (PKCS12Attribute, error) {
	// Encode as BMPString
	bmpData := make([]byte, 0, 2*len(name))
	for _, r := range name {
		bmpData = append(bmpData, byte(r/256), byte(r%256))
	}
	
	// Marshal as BMPString (tag 30)
	bmpValue, err := asn1.MarshalWithParams(bmpData, "tag:30")
	if err != nil {
		return PKCS12Attribute{}, err
	}
	
	return PKCS12Attribute{
		ID:     OIDFriendlyName,
		Values: [][]byte{bmpValue},
	}, nil
}

// createLocalKeyIDAttribute creates a localKeyID attribute
func createLocalKeyIDAttribute(keyID []byte) (PKCS12Attribute, error) {
	// Marshal as OCTET STRING
	keyIDValue, err := asn1.Marshal(keyID)
	if err != nil {
		return PKCS12Attribute{}, err
	}
	
	return PKCS12Attribute{
		ID:     OIDLocalKeyID,
		Values: [][]byte{keyIDValue},
	}, nil
}

// createDataContentInfo creates an unencrypted Data ContentInfo
func createDataContentInfo(data []byte) (ContentInfo, error) {
	// Wrap data in OCTET STRING and then context-specific [0]
	octetData, err := asn1.Marshal(data)
	if err != nil {
		return ContentInfo{}, err
	}
	
	return ContentInfo{
		ContentType: OIDData,
		Content:     octetData, // Parser expects raw OCTET STRING here
	}, nil
}

// createEncryptedContentInfo creates an encrypted EncryptedData ContentInfo
func createEncryptedContentInfo(data, password []byte, opts *EncodeOptions) (ContentInfo, error) {
	// For now, use unencrypted for certificates (common practice)
	// In the future, can add encryption support
	return createDataContentInfo(data)
}

// serializeSafeContents serializes SafeContents to DER
func serializeSafeContents(sc *SafeContents) ([]byte, error) {
	// SafeContents is a SEQUENCE OF SafeBag
	var rawBags []asn1.RawValue
	
	for _, bag := range sc.Bags {
		// Serialize each SafeBag
		bagData, err := serializeSafeBag(&bag)
		if err != nil {
			return nil, err
		}
		rawBags = append(rawBags, asn1.RawValue{FullBytes: bagData})
	}
	
	return asn1.Marshal(rawBags)
}

// serializeSafeBag serializes a SafeBag to DER
func serializeSafeBag(bag *SafeBag) ([]byte, error) {
	type safeBagASN1 struct {
		BagID      asn1.ObjectIdentifier
		BagValue   asn1.RawValue `asn1:"tag:0,explicit"`
		Attributes []asn1.RawValue `asn1:"set,optional"`
	}
	
	sb := safeBagASN1{
		BagID: bag.BagID,
		BagValue: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      bag.BagValue,
		},
	}
	
	// Serialize attributes
	if len(bag.Attributes) > 0 {
		for _, attr := range bag.Attributes {
			attrData, err := serializeAttribute(&attr)
			if err != nil {
				return nil, err
			}
			sb.Attributes = append(sb.Attributes, asn1.RawValue{FullBytes: attrData})
		}
	}
	
	return asn1.Marshal(sb)
}

// serializeAttribute serializes a PKCS12Attribute to DER
func serializeAttribute(attr *PKCS12Attribute) ([]byte, error) {
	type attributeASN1 struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	
	a := attributeASN1{
		ID: attr.ID,
	}
	
	for _, val := range attr.Values {
		a.Values = append(a.Values, asn1.RawValue{FullBytes: val})
	}
	
	return asn1.Marshal(a)
}

// serializeAuthenticatedSafe serializes AuthenticatedSafe to DER
func serializeAuthenticatedSafe(authSafe *AuthenticatedSafe) ([]byte, error) {
	// AuthenticatedSafe is a SEQUENCE OF ContentInfo
	var rawCIs []asn1.RawValue
	
	for _, ci := range authSafe.ContentInfos {
		ciData, err := serializeContentInfo(&ci)
		if err != nil {
			return nil, err
		}
		rawCIs = append(rawCIs, asn1.RawValue{FullBytes: ciData})
	}
	
	return asn1.Marshal(rawCIs)
}

// serializeContentInfo serializes ContentInfo to DER
func serializeContentInfo(ci *ContentInfo) ([]byte, error) {
	type contentInfoASN1 struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	
	ciASN := contentInfoASN1{
		ContentType: ci.ContentType,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      ci.Content,
		},
	}
	
	return asn1.Marshal(ciASN)
}

// serializePFX serializes PFX to DER
func serializePFX(pfx *PFX) ([]byte, error) {
	type pfxASN1 struct {
		Version  int
		AuthSafe asn1.RawValue
		MacData  asn1.RawValue `asn1:"optional"`
	}
	
	// Serialize AuthSafe ContentInfo
	authSafeData, err := serializeContentInfo(&pfx.AuthSafe)
	if err != nil {
		return nil, err
	}
	
	p := pfxASN1{
		Version:  pfx.Version,
		AuthSafe: asn1.RawValue{FullBytes: authSafeData},
	}
	
	// Add MAC if present
	if pfx.MacData != nil {
		macData, err := serializeMacData(pfx.MacData)
		if err != nil {
			return nil, err
		}
		p.MacData = asn1.RawValue{FullBytes: macData}
	}
	
	return asn1.Marshal(p)
}

// serializeMacData serializes MacData to DER
func serializeMacData(macData *MacData) ([]byte, error) {
	type macDataASN1 struct {
		Mac        asn1.RawValue
		MacSalt    []byte
		Iterations int `asn1:"optional,default:1"`
	}
	
	// Serialize DigestInfo
	digestData, err := serializeDigestInfo(&macData.Mac)
	if err != nil {
		return nil, err
	}
	
	md := macDataASN1{
		Mac:        asn1.RawValue{FullBytes: digestData},
		MacSalt:    macData.MacSalt,
		Iterations: macData.Iterations,
	}
	
	return asn1.Marshal(md)
}

// serializeDigestInfo serializes DigestInfo to DER
func serializeDigestInfo(di *DigestInfo) ([]byte, error) {
	type digestInfoASN1 struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	
	d := digestInfoASN1{
		Algorithm: di.Algorithm,
		Digest:    di.Digest,
	}
	
	return asn1.Marshal(d)
}

// generateMAC generates MAC for authenticated safe
func generateMAC(authSafeData, password []byte, opts *EncodeOptions) (*MacData, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	// Derive MAC key
	macKey, err := deriveMACKey(opts.MacAlgorithm, password, salt, opts.Iterations)
	if err != nil {
		return nil, err
	}
	
	// Get hash function
	hashFunc := getHashFunc(opts.MacAlgorithm)
	if hashFunc == nil {
		return nil, fmt.Errorf("%w: unsupported MAC algorithm", ErrUnsupportedAlgorithm)
	}
	
	// Compute MAC
	h := hmac.New(hashFunc, macKey)
	h.Write(authSafeData)
	digest := h.Sum(nil)
	
	return &MacData{
		Mac: DigestInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: opts.MacAlgorithm,
			},
			Digest: digest,
		},
		MacSalt:    salt,
		Iterations: opts.Iterations,
	}, nil
}

// encryptPrivateKey encrypts a private key using PBES2
func encryptPrivateKey(keyData, password []byte, opts *EncodeOptions) ([]byte, error) {
	// Generate random salt and IV
	salt := make([]byte, 16)
	iv := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	
	// Encrypt
	ciphertext, err := encryptPBES2(keyData, password, salt, iv, opts)
	if err != nil {
		return nil, err
	}
	
	// Store salt and IV in opts for buildPBES2AlgorithmIdentifier to use
	// This is a hack - better to return them
	opts.lastSalt = salt
	opts.lastIV = iv
	
	return ciphertext, nil
}

func encryptPBES2(data, password, salt, iv []byte, opts *EncodeOptions) ([]byte, error) {
	// Derive key using PBKDF2
	keyLen := getKeyLength(opts.KeyEncryption)
	if keyLen == 0 {
		return nil, fmt.Errorf("%w: unsupported cipher", ErrUnsupportedAlgorithm)
	}
	
	prfFunc := getPRFFunc(opts.MacAlgorithm)
	key := pbkdf2.Key(password, salt, opts.Iterations, keyLen, prfFunc)
	
	// Encrypt with AES-CBC
	return encryptAESCBC(key, iv, data)
}

// encryptAESCBC encrypts data using AES-CBC with PKCS#7 padding
func encryptAESCBC(key, iv, plaintext []byte) ([]byte, error) {
block, err := aes.NewCipher(key)
if err != nil {
return nil, fmt.Errorf("failed to create cipher: %w", err)
}

// Add PKCS#7 padding
padded := addPKCS7Padding(plaintext, aes.BlockSize)

// Encrypt
ciphertext := make([]byte, len(padded))
mode := cipher.NewCBCEncrypter(block, iv)
mode.CryptBlocks(ciphertext, padded)

return ciphertext, nil
}

// addPKCS7Padding adds PKCS#7 padding to data
func addPKCS7Padding(data []byte, blockSize int) []byte {
padding := blockSize - (len(data) % blockSize)
padText := make([]byte, padding)
for i := range padText {
padText[i] = byte(padding)
}
return append(data, padText...)
}

// buildPBES2AlgorithmIdentifier builds an AlgorithmIdentifier for PBES2
// buildPBES2AlgorithmIdentifier builds an AlgorithmIdentifier for PBES2
func buildPBES2AlgorithmIdentifier(opts *EncodeOptions) (pkix.AlgorithmIdentifier, error) {
// Build PBKDF2 parameters
pbkdf2Params := struct {
Salt           []byte
IterationCount int
KeyLength      int                       `asn1:"optional"`
PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}{
Salt:           opts.lastSalt,
IterationCount: opts.Iterations,
PRF: pkix.AlgorithmIdentifier{
Algorithm: opts.MacAlgorithm,
},
}

pbkdf2Data, err := asn1.Marshal(pbkdf2Params)
if err != nil {
return pkix.AlgorithmIdentifier{}, err
}

// Build cipher parameters (just IV for AES-CBC)
cipherParams, err := asn1.Marshal(opts.lastIV)
if err != nil {
return pkix.AlgorithmIdentifier{}, err
}

// Build PBES2 parameters
pbes2Params := struct {
KeyDerivationFunc pkix.AlgorithmIdentifier
EncryptionScheme  pkix.AlgorithmIdentifier
}{
KeyDerivationFunc: pkix.AlgorithmIdentifier{
Algorithm:  OIDPBKDF2,
Parameters: asn1.RawValue{FullBytes: pbkdf2Data},
},
EncryptionScheme: pkix.AlgorithmIdentifier{
Algorithm:  opts.KeyEncryption,
Parameters: asn1.RawValue{FullBytes: cipherParams},
},
}

pbes2Data, err := asn1.Marshal(pbes2Params)
if err != nil {
return pkix.AlgorithmIdentifier{}, err
}

return pkix.AlgorithmIdentifier{
Algorithm:  OIDPBES2,
Parameters: asn1.RawValue{FullBytes: pbes2Data},
}, nil
}
