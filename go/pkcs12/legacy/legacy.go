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

// Package legacy reads the PKCS#12 files that package pkcs12 rejects: files in
// BER encoding and files encrypted with RC2, two-key Triple DES or
// DES-EDE3-CBC in PBES2. Java keystores, Windows, OpenSSL's -legacy mode and
// the card vendors of the telematics infrastructure still write them.
//
// Decode accepts everything pkcs12.Decode accepts and returns the same Bags
// and the same error values, so callers can use it for every file. The legacy
// algorithms are read-only; to write a file, use pkcs12.Encode.
//
// Subpackage ber converts BER to DER, subpackage rc2 implements RC2.
package legacy

import (
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy/ber"
)

var (
	// PKCS#12 password-based encryption schemes this package decrypts in
	// addition to package pkcs12 (RFC 7292 appendix C).
	OIDPBEWithSHAAnd2KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	OIDPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}

	// OIDDESEDE3CBC is Triple DES as a PBES2 encryption scheme (RFC 8018 §B.2.2).
	OIDDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// Decode verifies, decrypts and extracts a PKCS#12 file in DER or BER
// encoding. It follows pkcs12.ExtractBags step by step and differs in two
// places only: every nested layer is converted from BER to DER before
// package pkcs12 parses it, and the legacy encryption schemes are decrypted
// here.
func Decode(data, password []byte) (*pkcs12.Bags, error) {
	der, err := ber.ToDER(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12: %w: %w", pkcs12.ErrInvalidPFX, err)
	}
	pfx, err := pkcs12.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12: %w", err)
	}
	if !pfx.AuthSafe.ContentType.Equal(pkcs12.OIDData) {
		return nil, fmt.Errorf("%w: authSafe content type %v (public-key integrity mode)", pkcs12.ErrUnsupportedAlgorithm, pfx.AuthSafe.ContentType)
	}
	// RawAuthSafe holds the authSafe octets with BER segments joined, which
	// are exactly the octets the MAC covers (RFC 7292 §4).
	if err := pkcs12.VerifyMAC(pfx, password); err != nil {
		return nil, fmt.Errorf("MAC verification failed: %w", err)
	}

	authSafeDER, err := toDER(pfx.RawAuthSafe)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticated safe: %w", err)
	}
	authSafe, err := pkcs12.ParseAuthenticatedSafe(authSafeDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticated safe: %w", err)
	}

	bags := &pkcs12.Bags{
		Certificates: make([]pkcs12.CertificateBag, 0),
		PrivateKeys:  make([]pkcs12.PrivateKeyBag, 0),
	}
	for _, ci := range authSafe.ContentInfos {
		var safe []byte
		switch {
		case ci.ContentType.Equal(pkcs12.OIDData):
			if safe, err = octetString(ci.Content); err != nil {
				return nil, fmt.Errorf("failed to extract safe contents: %w", err)
			}
		case ci.ContentType.Equal(pkcs12.OIDEncryptedData):
			if safe, err = decryptSafe(ci.Content, password); err != nil {
				return nil, fmt.Errorf("failed to decrypt safe contents: %w", err)
			}
		default:
			return nil, fmt.Errorf("%w: safe content type %v (public-key privacy mode)", pkcs12.ErrUnsupportedAlgorithm, ci.ContentType)
		}
		if err := collect(safe, password, bags); err != nil {
			return nil, err
		}
	}
	return bags, nil
}

// collect adds the certificates and keys of a SafeContents encoding to bags.
func collect(safe, password []byte, bags *pkcs12.Bags) error {
	safeDER, err := toDER(safe)
	if err != nil {
		return fmt.Errorf("failed to parse safe contents: %w", err)
	}
	sc, err := pkcs12.ParseSafeContents(safeDER)
	if err != nil {
		return fmt.Errorf("failed to parse safe contents: %w", err)
	}
	for _, bag := range sc.Bags {
		friendlyName, _ := pkcs12.GetFriendlyName(bag.Attributes)
		localKeyID, _ := pkcs12.GetLocalKeyID(bag.Attributes)

		switch {
		case bag.BagID.Equal(pkcs12.OIDCertBag):
			cb, err := pkcs12.ParseCertBag(bag.BagValue)
			if err != nil {
				return fmt.Errorf("failed to extract certificate: %w", err)
			}
			if !cb.CertID.Equal(pkcs12.OIDX509Certificate) {
				return fmt.Errorf("failed to extract certificate: %w: certificate type %v", pkcs12.ErrUnsupportedAlgorithm, cb.CertID)
			}
			bags.Certificates = append(bags.Certificates, pkcs12.CertificateBag{
				Raw: cb.CertValue, FriendlyName: friendlyName, LocalKeyID: localKeyID,
			})

		case bag.BagID.Equal(pkcs12.OIDPKCS8ShroudedKeyBag):
			epki, err := pkcs12.ParseEncryptedPrivateKeyInfo(bag.BagValue)
			if err != nil {
				return fmt.Errorf("failed to extract shrouded key: %w", err)
			}
			key, err := decrypt(epki.Algorithm, password, epki.Data)
			if err != nil {
				return fmt.Errorf("failed to extract shrouded key: %w", err)
			}
			bags.PrivateKeys = append(bags.PrivateKeys, pkcs12.PrivateKeyBag{
				Raw: key, FriendlyName: friendlyName, LocalKeyID: localKeyID,
			})

		case bag.BagID.Equal(pkcs12.OIDKeyBag):
			bags.PrivateKeys = append(bags.PrivateKeys, pkcs12.PrivateKeyBag{
				Raw: bag.BagValue, FriendlyName: friendlyName, LocalKeyID: localKeyID,
			})

		case bag.BagID.Equal(pkcs12.OIDSafeContentsBag):
			if err := collect(bag.BagValue, password, bags); err != nil {
				return err
			}
		}
	}
	return nil
}

// toDER converts a nested layer; its errors are parse errors of package pkcs12.
func toDER(data []byte) ([]byte, error) {
	der, err := ber.ToDER(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pkcs12.ErrParse, err)
	}
	return der, nil
}

// octetString returns the value of the OCTET STRING that makes up data.
func octetString(data []byte) ([]byte, error) {
	input := cryptobyte.String(data)
	var value []byte
	if !input.ReadASN1Bytes(&value, cryptobyte_asn1.OCTET_STRING) || !input.Empty() {
		return nil, fmt.Errorf("%w: cannot read OCTET STRING", pkcs12.ErrParse)
	}
	return value, nil
}

// ConvertWithOpenSSL re-encodes a PKCS#12 file the way `openssl pkcs12
// -legacy` followed by `openssl pkcs12 -export` did: DER, PBES2 with
// AES-256-CBC, an HMAC-SHA-256 MAC, the same password. Despite its name it no
// longer runs OpenSSL.
//
// Deprecated: Decode reads BER and legacy algorithms directly; to write a
// modern file, pass its result to pkcs12.Encode.
func ConvertWithOpenSSL(data []byte, password string) ([]byte, error) {
	bags, err := Decode(data, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("legacy: %w", err)
	}
	out, err := pkcs12.Encode(bags, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("legacy: %w", err)
	}
	return out, nil
}

// IsBER reports whether data starts with an indefinite-length SEQUENCE, the
// usual sign of a BER-encoded PKCS#12 file.
func IsBER(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x30 && data[1] == 0x80
}
