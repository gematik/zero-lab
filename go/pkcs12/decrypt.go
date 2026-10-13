// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package pkcs12

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // Triple DES is read for legacy files only.
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // SHA-1 is the hash of the PKCS#12 PBEs and of legacy MACs.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"github.com/gematik/zero-lab/go/pkcs12/internal/pbe"
)

var (
	// ErrDecryption reports ciphertext that does not decrypt: a wrong
	// password in a file without MAC, or corrupt data.
	ErrDecryption = errors.New("pkcs12: decryption failed")
	// ErrAuthentication reports a MAC mismatch: a wrong password or an
	// altered file.
	ErrAuthentication = errors.New("pkcs12: MAC verification failed")
	// ErrInvalidPadding reports invalid PKCS#7 padding after decryption; it
	// comes wrapped together with ErrDecryption.
	ErrInvalidPadding = errors.New("pkcs12: invalid padding")
)

// pbes2Cipher is an encryption scheme of PBES2.
type pbes2Cipher struct {
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

func pbes2CipherFor(oid asn1.ObjectIdentifier) (pbes2Cipher, bool) {
	switch {
	case oid.Equal(OIDAes128CBC):
		return pbes2Cipher{16, aes.NewCipher}, true
	case oid.Equal(OIDAes192CBC):
		return pbes2Cipher{24, aes.NewCipher}, true
	case oid.Equal(OIDAes256CBC):
		return pbes2Cipher{32, aes.NewCipher}, true
	}
	return pbes2Cipher{}, false
}

// pbkdf2PRF returns the hash of a PBKDF2 PRF (RFC 8018 §B.1).
func pbkdf2PRF(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	if prf, ok := pbe.PBKDF2PRF(oid); ok {
		return prf, nil
	}
	return nil, fmt.Errorf("%w: PBKDF2 PRF %v", ErrUnsupportedAlgorithm, oid)
}

// legacyPBE is a PKCS#12 password-based encryption scheme (RFC 7292
// appendix C): key and IV come from the PKCS#12 KDF with SHA-1.
type legacyPBE struct {
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

// legacyPBEFor knows three-key Triple DES only; package legacy adds RC2 and
// two-key Triple DES.
func legacyPBEFor(oid asn1.ObjectIdentifier) (legacyPBE, bool) {
	if oid.Equal(OIDPBEWithSHAAnd3KeyTripleDESCBC) {
		return legacyPBE{24, des.NewTripleDESCipher}, true
	}
	return legacyPBE{}, false
}

// DecryptPBES2 decrypts data encrypted with PBES2 (RFC 8018 §6.2).
func DecryptPBES2(encAlg *EncryptionAlgorithm, password []byte, data []byte) ([]byte, error) {
	if encAlg.KDF == nil || encAlg.Cipher == nil {
		return nil, fmt.Errorf("%w: incomplete PBES2 parameters", ErrDecryption)
	}
	c, ok := pbes2CipherFor(encAlg.Cipher.Algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: PBES2 encryption scheme %v", ErrUnsupportedAlgorithm, encAlg.Cipher.Algorithm)
	}
	prf, err := pbkdf2PRF(encAlg.KDF.PRF)
	if err != nil {
		return nil, err
	}
	if encAlg.KDF.KeyLength != 0 && encAlg.KDF.KeyLength != c.keySize {
		return nil, fmt.Errorf("%w: PBKDF2 keyLength %d does not fit the cipher", ErrParse, encAlg.KDF.KeyLength)
	}
	if err := checkIterations(encAlg.KDF.Iterations); err != nil {
		return nil, err
	}
	// PBES2 feeds the password octets to PBKDF2 unchanged (RFC 8018 §6.2.1);
	// only the PKCS#12 KDF uses the BMPString form.
	key, err := pbkdf2.Key(prf, string(password), encAlg.KDF.Salt, encAlg.KDF.Iterations, c.keySize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryption, err)
	}
	block, err := c.newBlock(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryption, err)
	}
	return decryptCBC(block, encAlg.Cipher.IV, data)
}

// DecryptLegacyPBE decrypts data encrypted with pbeWithSHAAnd3-KeyTripleDES-CBC.
// RC2 and two-key Triple DES are decrypted by package legacy.
func DecryptLegacyPBE(encAlg *EncryptionAlgorithm, password []byte, data []byte) ([]byte, error) {
	scheme, ok := legacyPBEFor(encAlg.Algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: encryption scheme %v", ErrUnsupportedAlgorithm, encAlg.Algorithm)
	}
	if err := checkIterations(encAlg.Iterations); err != nil {
		return nil, err
	}
	bmp := pbe.BMPPassword(password)
	key := pbe.PKCS12KDF(sha1.New, bmp, encAlg.Salt, encAlg.Iterations, pbe.PurposeKey, scheme.keySize)
	block, err := scheme.newBlock(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryption, err)
	}
	iv := pbe.PKCS12KDF(sha1.New, bmp, encAlg.Salt, encAlg.Iterations, pbe.PurposeIV, block.BlockSize())
	return decryptCBC(block, iv, data)
}

// decryptWith decrypts data with the scheme alg names.
func decryptWith(alg *EncryptionAlgorithm, password, data []byte) ([]byte, error) {
	if alg.Algorithm.Equal(OIDPBES2) {
		return DecryptPBES2(alg, password, data)
	}
	return DecryptLegacyPBE(alg, password, data)
}

// DecryptEncryptedData decrypts a safe whose ContentInfo is EncryptedData
// and returns the SafeContents encoding.
func DecryptEncryptedData(contentInfo ContentInfo, password []byte) ([]byte, error) {
	if !contentInfo.ContentType.Equal(OIDEncryptedData) {
		return nil, fmt.Errorf("%w: content type %v is not EncryptedData", ErrDecryption, contentInfo.ContentType)
	}
	algID, ciphertext, err := parseEncryptedData(contentInfo.Content)
	if err != nil {
		return nil, err
	}
	alg, err := ParseEncryptionAlgorithm(algID)
	if err != nil {
		return nil, err
	}
	return decryptWith(alg, password, ciphertext)
}

// DecryptShroudedKeyBag decrypts the value of a shrouded key bag and returns
// the PKCS#8 PrivateKeyInfo.
func DecryptShroudedKeyBag(bagValue []byte, password []byte) ([]byte, error) {
	epki, err := ParseEncryptedPrivateKeyInfo(bagValue)
	if err != nil {
		return nil, err
	}
	alg, err := ParseEncryptionAlgorithm(epki.Algorithm)
	if err != nil {
		return nil, err
	}
	return decryptWith(alg, password, epki.Data)
}

// decryptCBC decrypts CBC and removes the PKCS#7 padding.
func decryptCBC(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	plaintext, err := pbe.DecryptCBC(block, iv, ciphertext)
	switch {
	case errors.Is(err, pbe.ErrPadding):
		return nil, fmt.Errorf("%w: %w", ErrDecryption, ErrInvalidPadding)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrDecryption, err)
	}
	return plaintext, nil
}

// checkIterations bounds an iteration count read from a file, see
// pbe.MaxIterations.
func checkIterations(n int) error {
	if n < 1 {
		return fmt.Errorf("%w: iteration count %d", ErrParse, n)
	}
	if n > pbe.MaxIterations {
		return fmt.Errorf("%w: iteration count %d above %d", ErrLimitExceeded, n, pbe.MaxIterations)
	}
	return nil
}

// macHash returns the hash of a PKCS#12 MAC digest algorithm (RFC 7292 §5,
// appendix B.4). The HMAC OIDs are accepted too: some producers, including
// this package up to v0.99.3, wrote them in place of the digest OIDs.
func macHash(alg asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case alg.Equal(OIDSHA1), alg.Equal(OIDHMACSHA1):
		return sha1.New, nil
	case alg.Equal(OIDSHA224), alg.Equal(OIDHMACSHA224):
		return sha256.New224, nil
	case alg.Equal(OIDSHA256), alg.Equal(OIDHMACSHA256):
		return sha256.New, nil
	case alg.Equal(OIDSHA384), alg.Equal(OIDHMACSHA384):
		return sha512.New384, nil
	case alg.Equal(OIDSHA512), alg.Equal(OIDHMACSHA512):
		return sha512.New, nil
	}
	return nil, fmt.Errorf("%w: MAC algorithm %v", ErrUnsupportedAlgorithm, alg)
}

// computeMAC is the password integrity mode of RFC 7292 §5: HMAC over the
// authSafe octets with a key from the PKCS#12 KDF, as long as the digest.
func computeMAC(alg asn1.ObjectIdentifier, password, salt []byte, iterations int, data []byte) ([]byte, error) {
	newHash, err := macHash(alg)
	if err != nil {
		return nil, err
	}
	if err := checkIterations(iterations); err != nil {
		return nil, err
	}
	key := pbe.PKCS12KDF(newHash, pbe.BMPPassword(password), salt, iterations, pbe.PurposeMAC, newHash().Size())
	mac := hmac.New(newHash, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyMAC checks the MAC of pfx. A PFX without MacData has no integrity
// protection and passes; callers that require one check pfx.MacData.
func VerifyMAC(pfx *PFX, password []byte) error {
	if pfx.MacData == nil {
		return nil
	}
	md := pfx.MacData
	expected, err := computeMAC(md.Mac.Algorithm.Algorithm, password, md.MacSalt, md.Iterations, pfx.RawAuthSafe)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, md.Mac.Digest) {
		return ErrAuthentication
	}
	return nil
}
