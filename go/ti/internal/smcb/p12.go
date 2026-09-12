package smcb

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
)

// FromP12 loads the C.AUT identity from a PKCS#12 file. Legacy BER bundles
// are converted through OpenSSL first. alias names the cert/key pair by
// FriendlyName; with the default alias and several pairs in the bundle the
// C.AUT pair is picked.
func FromP12(path, alias, password string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if legacy.IsBER(data) {
		converted, err := legacy.ConvertWithOpenSSL(data, password)
		if err != nil {
			return nil, fmt.Errorf("converting legacy BER PKCS#12: %w", err)
		}
		data = converted
	}
	bags, err := pkcs12.Decode(data, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("decoding PKCS#12: %w", err)
	}

	cert, key, err := selectPair(bags, alias)
	if err != nil {
		return nil, err
	}
	rawKey, err := brainpool.ParsePKCS8PrivateKey(key.Raw)
	if err != nil {
		return nil, fmt.Errorf("parsing C.AUT private key: %w", err)
	}
	parsedKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("C.AUT private key is %T, want *ecdsa.PrivateKey", rawKey)
	}
	return &Identity{
		Sign:   brainpool.SignFuncPrivateKey(parsedKey),
		Cert:   func() (*x509.Certificate, error) { return cert, nil },
		Source: path,
	}, nil
}

// selectPair picks a certificate and its private key. A single pair wins
// regardless of alias (single-identity bundles rarely bother with friendly
// names); otherwise the alias is matched by FriendlyName, and when the
// alias is the default, the C.AUT certificate is preferred — an SMC-B
// bundle also carries C.ENC and C.OSIG, which sign nothing here.
func selectPair(bags *pkcs12.Bags, alias string) (*x509.Certificate, *pkcs12.PrivateKeyBag, error) {
	if len(bags.Certificates) == 0 {
		return nil, nil, fmt.Errorf("PKCS#12 file contains no certificates")
	}
	if len(bags.PrivateKeys) == 0 {
		return nil, nil, fmt.Errorf("PKCS#12 file contains no private keys")
	}

	var bag *pkcs12.CertificateBag
	switch {
	case len(bags.Certificates) == 1 && len(bags.PrivateKeys) == 1:
		bag = &bags.Certificates[0]
	case alias != DefaultAlias:
		bag = findCertByName(bags, alias)
		if bag == nil {
			return nil, nil, fmt.Errorf("no certificate with FriendlyName %q in PKCS#12 file", alias)
		}
	default:
		bag = findCertByName(bags, alias)
		if bag == nil {
			bag = findAuthCert(bags)
		}
		if bag == nil {
			return nil, nil, fmt.Errorf("PKCS#12 file holds %d certificates and none is a C.AUT; pass --%s", len(bags.Certificates), P12AliasFlag)
		}
	}

	cert, err := brainpool.ParseCertificate(bag.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing C.AUT cert: %w", err)
	}
	key := findKeyForCert(bags, bag)
	if key == nil {
		return nil, nil, fmt.Errorf("no private key matching certificate %q in PKCS#12 file", cert.Subject.CommonName)
	}
	return cert, key, nil
}

// findAuthCert returns the first EC certificate that signs but does not
// commit: digitalSignature without contentCommitment (nonRepudiation) is how
// gemSpec_PKI tells C.AUT from C.OSIG/C.QES, and C.ENC has neither.
func findAuthCert(bags *pkcs12.Bags) *pkcs12.CertificateBag {
	for i := range bags.Certificates {
		cert, err := brainpool.ParseCertificate(bags.Certificates[i].Raw)
		if err != nil {
			continue
		}
		if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			continue
		}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 && cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
			return &bags.Certificates[i]
		}
	}
	return nil
}

func findCertByName(bags *pkcs12.Bags, name string) *pkcs12.CertificateBag {
	for i := range bags.Certificates {
		if bags.Certificates[i].FriendlyName == name {
			return &bags.Certificates[i]
		}
	}
	return nil
}

func findKeyForCert(bags *pkcs12.Bags, cert *pkcs12.CertificateBag) *pkcs12.PrivateKeyBag {
	// Prefer LocalKeyID match (standard pairing); fall back to FriendlyName.
	if len(cert.LocalKeyID) > 0 {
		for i := range bags.PrivateKeys {
			if bytes.Equal(bags.PrivateKeys[i].LocalKeyID, cert.LocalKeyID) {
				return &bags.PrivateKeys[i]
			}
		}
	}
	for i := range bags.PrivateKeys {
		if bags.PrivateKeys[i].FriendlyName != "" && bags.PrivateKeys[i].FriendlyName == cert.FriendlyName {
			return &bags.PrivateKeys[i]
		}
	}
	return nil
}
