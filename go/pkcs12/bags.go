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
	"bytes"
	"fmt"
)

// CertificateBag is a certificate of a PKCS#12 file with its attributes.
type CertificateBag struct {
	// Raw is the DER-encoded X.509 certificate.
	Raw []byte
	// FriendlyName is the friendlyName attribute, empty when absent.
	FriendlyName string
	// LocalKeyID is the localKeyId attribute that links the certificate to
	// its private key, nil when absent.
	LocalKeyID []byte
}

// PrivateKeyBag is a private key of a PKCS#12 file with its attributes.
type PrivateKeyBag struct {
	// Raw is the DER-encoded PKCS#8 PrivateKeyInfo.
	Raw []byte
	// FriendlyName is the friendlyName attribute, empty when absent.
	FriendlyName string
	// LocalKeyID is the localKeyId attribute that links the key to its
	// certificate, nil when absent.
	LocalKeyID []byte
}

// Bags holds the certificates and private keys of a PKCS#12 file.
type Bags struct {
	Certificates []CertificateBag
	PrivateKeys  []PrivateKeyBag
}

// CertKeyPair is a certificate and the private key with the same localKeyId.
type CertKeyPair struct {
	Certificate *CertificateBag
	PrivateKey  *PrivateKeyBag
}

// Decode verifies, decrypts and extracts a PKCS#12 file in one step; it is
// Parse followed by ExtractBags. DER and BER encodings are accepted.
//
// Parse the results with crypto/x509: x509.ParseCertificate(cert.Raw) and
// x509.ParsePKCS8PrivateKey(key.Raw).
func Decode(data, password []byte) (*Bags, error) {
	pfx, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12: %w", err)
	}
	return ExtractBags(pfx, password)
}

// ExtractBags verifies the MAC of pfx, if present, then decrypts every safe
// and returns the certificates and keys. Only the password integrity and
// privacy modes are supported; a signed authSafe or an enveloped safe yields
// ErrUnsupportedAlgorithm. CRL, secret and unknown bags are skipped.
func ExtractBags(pfx *PFX, password []byte) (*Bags, error) {
	if !pfx.AuthSafe.ContentType.Equal(OIDData) {
		return nil, fmt.Errorf("%w: authSafe content type %v (public-key integrity mode)", ErrUnsupportedAlgorithm, pfx.AuthSafe.ContentType)
	}
	// The MAC is checked before anything inside the authSafe is parsed, so
	// a tampered file never reaches the decoders.
	if err := VerifyMAC(pfx, password); err != nil {
		return nil, fmt.Errorf("MAC verification failed: %w", err)
	}

	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticated safe: %w", err)
	}

	bags := &Bags{
		Certificates: make([]CertificateBag, 0),
		PrivateKeys:  make([]PrivateKeyBag, 0),
	}
	for _, ci := range authSafe.ContentInfos {
		var safe []byte
		switch {
		case ci.ContentType.Equal(OIDData):
			if safe, err = extractOctetString(ci.Content); err != nil {
				return nil, fmt.Errorf("failed to extract safe contents: %w", err)
			}
		case ci.ContentType.Equal(OIDEncryptedData):
			if safe, err = DecryptEncryptedData(ci, password); err != nil {
				return nil, fmt.Errorf("failed to decrypt safe contents: %w", err)
			}
		default:
			return nil, fmt.Errorf("%w: safe content type %v (public-key privacy mode)", ErrUnsupportedAlgorithm, ci.ContentType)
		}

		sc, err := ParseSafeContents(safe)
		if err != nil {
			return nil, fmt.Errorf("failed to parse safe contents: %w", err)
		}
		if err := collectBags(sc, password, bags); err != nil {
			return nil, err
		}
	}
	return bags, nil
}

// collectBags adds the certificates and keys of sc to bags, descending into
// nested safe contents bags.
func collectBags(sc *SafeContents, password []byte, bags *Bags) error {
	for _, bag := range sc.Bags {
		friendlyName, _ := GetFriendlyName(bag.Attributes)
		localKeyID, _ := GetLocalKeyID(bag.Attributes)

		switch {
		case bag.BagID.Equal(OIDCertBag):
			cb, err := ParseCertBag(bag.BagValue)
			if err != nil {
				return fmt.Errorf("failed to extract certificate: %w", err)
			}
			if !cb.CertID.Equal(OIDX509Certificate) {
				return fmt.Errorf("failed to extract certificate: %w: certificate type %v", ErrUnsupportedAlgorithm, cb.CertID)
			}
			bags.Certificates = append(bags.Certificates, CertificateBag{
				Raw: cb.CertValue, FriendlyName: friendlyName, LocalKeyID: localKeyID,
			})

		case bag.BagID.Equal(OIDPKCS8ShroudedKeyBag):
			key, err := DecryptShroudedKeyBag(bag.BagValue, password)
			if err != nil {
				return fmt.Errorf("failed to extract shrouded key: %w", err)
			}
			bags.PrivateKeys = append(bags.PrivateKeys, PrivateKeyBag{
				Raw: key, FriendlyName: friendlyName, LocalKeyID: localKeyID,
			})

		case bag.BagID.Equal(OIDKeyBag):
			// A KeyBag holds the PKCS#8 PrivateKeyInfo in the clear.
			bags.PrivateKeys = append(bags.PrivateKeys, PrivateKeyBag{
				Raw: bag.BagValue, FriendlyName: friendlyName, LocalKeyID: localKeyID,
			})

		case bag.BagID.Equal(OIDSafeContentsBag):
			nested, err := ParseSafeContents(bag.BagValue)
			if err != nil {
				return fmt.Errorf("failed to parse nested safe contents: %w", err)
			}
			if err := collectBags(nested, password, bags); err != nil {
				return err
			}
		}
	}
	return nil
}

// FindCertificate returns the certificate with the given localKeyId, or nil.
func (b *Bags) FindCertificate(localKeyID []byte) *CertificateBag {
	for i := range b.Certificates {
		if bytes.Equal(b.Certificates[i].LocalKeyID, localKeyID) {
			return &b.Certificates[i]
		}
	}
	return nil
}

// FindPrivateKey returns the private key with the given localKeyId, or nil.
func (b *Bags) FindPrivateKey(localKeyID []byte) *PrivateKeyBag {
	for i := range b.PrivateKeys {
		if bytes.Equal(b.PrivateKeys[i].LocalKeyID, localKeyID) {
			return &b.PrivateKeys[i]
		}
	}
	return nil
}

// FindMatchingPairs pairs every certificate that has a localKeyId with the
// private key of the same localKeyId, in certificate order.
func (b *Bags) FindMatchingPairs() []CertKeyPair {
	pairs := make([]CertKeyPair, 0)
	for i := range b.Certificates {
		cert := &b.Certificates[i]
		if len(cert.LocalKeyID) == 0 {
			continue
		}
		if key := b.FindPrivateKey(cert.LocalKeyID); key != nil {
			pairs = append(pairs, CertKeyPair{Certificate: cert, PrivateKey: key})
		}
	}
	return pairs
}
