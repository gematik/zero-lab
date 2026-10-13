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

package legacy

import (
	"crypto/cipher"
	"crypto/des" //nolint:gosec // Triple DES is what the files this package exists for use.
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // The PKCS#12 PBEs derive keys with SHA-1.
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/internal/pbe"
	"github.com/gematik/zero-lab/go/pkcs12/legacy/rc2"
)

// decrypt decrypts data with the scheme alg names: the legacy schemes here,
// everything else through package pkcs12.
func decrypt(alg pkix.AlgorithmIdentifier, password, data []byte) ([]byte, error) {
	if scheme, ok := legacyPBEFor(alg.Algorithm); ok {
		salt, iterations, err := parsePBEParams(alg.Parameters.FullBytes)
		if err != nil {
			return nil, err
		}
		return decryptPBE(scheme, password, salt, iterations, data)
	}

	ea, err := pkcs12.ParseEncryptionAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	if ea.Algorithm.Equal(pkcs12.OIDPBES2) {
		if ea.Cipher.Algorithm.Equal(OIDDESEDE3CBC) {
			return decryptPBES2TripleDES(ea, password, data)
		}
		return pkcs12.DecryptPBES2(ea, password, data)
	}
	return pkcs12.DecryptLegacyPBE(ea, password, data)
}

// decryptSafe decrypts a PKCS#7 EncryptedData (RFC 2315 §13) and returns the
// SafeContents encoding.
func decryptSafe(content, password []byte) ([]byte, error) {
	// EncryptedData ::= SEQUENCE { version INTEGER, encryptedContentInfo SEQUENCE {
	//   contentType OBJECT IDENTIFIER, contentEncryptionAlgorithm AlgorithmIdentifier,
	//   encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL } }
	input := cryptobyte.String(content)
	var seq, info, algDER cryptobyte.String
	var version int
	var contentType asn1.ObjectIdentifier
	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!seq.ReadASN1Integer(&version) ||
		!seq.ReadASN1(&info, cryptobyte_asn1.SEQUENCE) || !seq.Empty() ||
		!info.ReadASN1ObjectIdentifier(&contentType) ||
		!info.ReadASN1Element(&algDER, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: cannot read EncryptedData", pkcs12.ErrParse)
	}
	if version != 0 {
		return nil, fmt.Errorf("%w: unsupported EncryptedData version %d", pkcs12.ErrDecryption, version)
	}
	var alg pkix.AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(algDER, &alg); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("%w: cannot read contentEncryptionAlgorithm", pkcs12.ErrParse)
	}
	ciphertext, err := encryptedContent(&info)
	if err != nil {
		return nil, err
	}
	return decrypt(alg, password, ciphertext)
}

// encryptedContent reads encryptedContent [0] IMPLICIT OCTET STRING. BER
// producers write it constructed, as a [0] holding OCTET STRING segments. The
// BER conversion keeps that form, since only the schema tells that this [0]
// is a string, so the segments are joined here.
func encryptedContent(s *cryptobyte.String) ([]byte, error) {
	primitive := cryptobyte_asn1.Tag(0).ContextSpecific()
	var content []byte
	switch {
	case s.PeekASN1Tag(primitive):
		if !s.ReadASN1Bytes(&content, primitive) {
			return nil, fmt.Errorf("%w: cannot read encryptedContent", pkcs12.ErrParse)
		}
	case s.PeekASN1Tag(primitive.Constructed()):
		var segments cryptobyte.String
		if !s.ReadASN1(&segments, primitive.Constructed()) {
			return nil, fmt.Errorf("%w: cannot read encryptedContent", pkcs12.ErrParse)
		}
		for !segments.Empty() {
			var segment []byte
			if !segments.ReadASN1Bytes(&segment, cryptobyte_asn1.OCTET_STRING) {
				return nil, fmt.Errorf("%w: cannot read an encryptedContent segment", pkcs12.ErrParse)
			}
			content = append(content, segment...)
		}
	default:
		return nil, fmt.Errorf("%w: EncryptedData without encryptedContent", pkcs12.ErrParse)
	}
	if !s.Empty() {
		return nil, fmt.Errorf("%w: trailing data in EncryptedContentInfo", pkcs12.ErrParse)
	}
	return content, nil
}

// legacyPBE is a PKCS#12 password-based encryption scheme (RFC 7292
// appendix C) that package pkcs12 does not decrypt.
type legacyPBE struct {
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

func legacyPBEFor(oid asn1.ObjectIdentifier) (legacyPBE, bool) {
	switch {
	case oid.Equal(OIDPBEWithSHAAnd2KeyTripleDESCBC):
		// Two-key Triple DES is K1 K2 K1.
		return legacyPBE{16, func(key []byte) (cipher.Block, error) {
			return des.NewTripleDESCipher(append(key[:16:16], key[:8]...))
		}}, true
	case oid.Equal(pkcs12.OIDPBEWithSHAAnd128BitRC2CBC):
		return legacyPBE{16, func(key []byte) (cipher.Block, error) { return rc2.New(key, 128) }}, true
	case oid.Equal(OIDPBEWithSHAAnd40BitRC2CBC):
		return legacyPBE{5, func(key []byte) (cipher.Block, error) { return rc2.New(key, 40) }}, true
	}
	return legacyPBE{}, false
}

func parsePBEParams(params []byte) ([]byte, int, error) {
	// pkcs-12PbeParams ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
	input := cryptobyte.String(params)
	var seq cryptobyte.String
	var salt []byte
	var iterations int
	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!seq.ReadASN1Bytes(&salt, cryptobyte_asn1.OCTET_STRING) ||
		!seq.ReadASN1Integer(&iterations) || !seq.Empty() {
		return nil, 0, fmt.Errorf("%w: cannot read PKCS#12 PBE parameters", pkcs12.ErrParse)
	}
	return salt, iterations, nil
}

func decryptPBE(scheme legacyPBE, password, salt []byte, iterations int, data []byte) ([]byte, error) {
	if err := checkIterations(iterations); err != nil {
		return nil, err
	}
	bmp := pbe.BMPPassword(password)
	key := pbe.PKCS12KDF(sha1.New, bmp, salt, iterations, pbe.PurposeKey, scheme.keySize)
	block, err := scheme.newBlock(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pkcs12.ErrDecryption, err)
	}
	iv := pbe.PKCS12KDF(sha1.New, bmp, salt, iterations, pbe.PurposeIV, block.BlockSize())
	return decryptCBC(block, iv, data)
}

func decryptPBES2TripleDES(ea *pkcs12.EncryptionAlgorithm, password, data []byte) ([]byte, error) {
	prf, ok := pbe.PBKDF2PRF(ea.KDF.PRF)
	if !ok {
		return nil, fmt.Errorf("%w: PBKDF2 PRF %v", pkcs12.ErrUnsupportedAlgorithm, ea.KDF.PRF)
	}
	if ea.KDF.KeyLength != 0 && ea.KDF.KeyLength != 24 {
		return nil, fmt.Errorf("%w: PBKDF2 keyLength %d does not fit DES-EDE3", pkcs12.ErrParse, ea.KDF.KeyLength)
	}
	if err := checkIterations(ea.KDF.Iterations); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(prf, string(password), ea.KDF.Salt, ea.KDF.Iterations, 24)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pkcs12.ErrDecryption, err)
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pkcs12.ErrDecryption, err)
	}
	return decryptCBC(block, ea.Cipher.IV, data)
}

func decryptCBC(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	plaintext, err := pbe.DecryptCBC(block, iv, ciphertext)
	switch {
	case errors.Is(err, pbe.ErrPadding):
		return nil, fmt.Errorf("%w: %w", pkcs12.ErrDecryption, pkcs12.ErrInvalidPadding)
	case err != nil:
		return nil, fmt.Errorf("%w: %w", pkcs12.ErrDecryption, err)
	}
	return plaintext, nil
}

func checkIterations(n int) error {
	if n < 1 {
		return fmt.Errorf("%w: iteration count %d", pkcs12.ErrParse, n)
	}
	if n > pbe.MaxIterations {
		return fmt.Errorf("%w: iteration count %d above %d", pkcs12.ErrLimitExceeded, n, pbe.MaxIterations)
	}
	return nil
}
