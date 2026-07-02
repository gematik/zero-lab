package epa

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
)

type p12AuthMethod struct {
	path     string
	alias    string
	password string
}

func newP12AuthMethod(path, alias, password string) AuthMethod {
	return &p12AuthMethod{path: path, alias: alias, password: password}
}

func (p *p12AuthMethod) Name() string { return authMethodP12 }

func (p *p12AuthMethod) SecurityFunctions(ctx context.Context) (*epa.SecurityFunctions, error) {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.path, err)
	}
	if legacy.IsBER(data) {
		converted, err := legacy.ConvertWithOpenSSL(data, p.password)
		if err != nil {
			return nil, fmt.Errorf("converting legacy BER PKCS#12: %w", err)
		}
		data = converted
	}
	bags, err := pkcs12.Decode(data, []byte(p.password))
	if err != nil {
		return nil, fmt.Errorf("decoding PKCS#12: %w", err)
	}

	cert, key, err := selectP12Pair(bags, p.alias)
	if err != nil {
		return nil, err
	}

	parsedCert, err := brainpool.ParseCertificate(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("parsing C.AUT cert: %w", err)
	}
	rawKey, err := brainpool.ParsePKCS8PrivateKey(key.Raw)
	if err != nil {
		return nil, fmt.Errorf("parsing C.AUT private key: %w", err)
	}
	parsedKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("C.AUT private key is %T, want *ecdsa.PrivateKey", rawKey)
	}

	signFn := brainpool.SignFuncPrivateKey(parsedKey)
	certFn := func() (*x509.Certificate, error) { return parsedCert, nil }

	return &epa.SecurityFunctions{
		AuthnSignFunc:           signFn,
		AuthnCertFunc:           certFn,
		ClientAssertionSignFunc: signFn,
		ClientAssertionCertFunc: certFn,
		// ProvidePN and ProvideHCV intentionally nil — entitlement is wired elsewhere.
	}, nil
}

// selectP12Pair picks a cert/private-key bag pair by FriendlyName. When the
// alias is the default and the bundle has exactly one pair, the alias is
// ignored (covers single-identity p12s that don't bother with friendly names).
func selectP12Pair(bags *pkcs12.Bags, alias string) (*pkcs12.CertificateBag, *pkcs12.PrivateKeyBag, error) {
	if len(bags.Certificates) == 0 {
		return nil, nil, fmt.Errorf("PKCS#12 file contains no certificates")
	}
	if len(bags.PrivateKeys) == 0 {
		return nil, nil, fmt.Errorf("PKCS#12 file contains no private keys")
	}

	// Single-pair shortcut: skip name matching when there's only one of each.
	if len(bags.Certificates) == 1 && len(bags.PrivateKeys) == 1 {
		return &bags.Certificates[0], &bags.PrivateKeys[0], nil
	}

	cert := findCertByName(bags, alias)
	if cert == nil {
		return nil, nil, fmt.Errorf("no certificate with FriendlyName %q in PKCS#12 file", alias)
	}
	key := findKeyForCert(bags, cert)
	if key == nil {
		return nil, nil, fmt.Errorf("no private key matching certificate %q in PKCS#12 file", alias)
	}
	return cert, key, nil
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
