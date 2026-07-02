package epa

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
)

// LoadIdentityP12 loads the SMC-B authentication (AUT) identity from a PKCS#12 file: the EC
// certificate with KeyUsage digitalSignature set (and contentCommitment unset, which marks the
// OSIG cert) plus its matching Brainpool private key. The repo's brainpool parsers are used because
// stdlib crypto/x509 does not know the Brainpool curves. Legacy BER-encoded PKCS#12 (older gematik
// test cards) is converted via OpenSSL first.
func LoadIdentityP12(path, password string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if legacy.IsBER(data) {
		converted, err := legacy.ConvertWithOpenSSL(data, password)
		if err != nil {
			return nil, nil, fmt.Errorf("converting legacy BER PKCS#12: %w", err)
		}
		data = converted
	}
	bags, err := pkcs12.Decode(data, []byte(password))
	if err != nil {
		return nil, nil, fmt.Errorf("decoding PKCS#12: %w", err)
	}

	// Parse every private key (Brainpool-aware).
	var keys []*ecdsa.PrivateKey
	for _, kb := range bags.PrivateKeys {
		raw, err := brainpool.ParsePKCS8PrivateKey(kb.Raw)
		if err != nil {
			continue
		}
		if k, ok := raw.(*ecdsa.PrivateKey); ok {
			keys = append(keys, k)
		}
	}

	for _, cb := range bags.Certificates {
		cert, err := brainpool.ParseCertificate(cb.Raw)
		if err != nil {
			continue // CA / unparseable
		}
		// AUT: digitalSignature set, contentCommitment (OSIG) not set.
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			continue
		}
		if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
			continue
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		for _, k := range keys {
			if k.PublicKey.X.Cmp(pub.X) == 0 && k.PublicKey.Y.Cmp(pub.Y) == 0 {
				return k, cert, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no AUT identity (EC digitalSignature cert + matching key) found in %s", path)
}

// SecurityFunctionsFromP12 builds SecurityFunctions backed by the AUT identity in a PKCS#12 file.
// ProvidePN/ProvideHCV are supplied by the caller — entitlement needs VSDM material that is not in
// the p12 — and may be nil when only the VAU handshake, authorization, and /information endpoints
// are exercised.
func SecurityFunctionsFromP12(path, password string, provideHCV ProvideHCVFunc, providePN ProvidePNFunc) (*SecurityFunctions, error) {
	key, cert, err := LoadIdentityP12(path, password)
	if err != nil {
		return nil, err
	}
	signFn := brainpool.SignFuncPrivateKey(key)
	certFn := func() (*x509.Certificate, error) { return cert, nil }
	return &SecurityFunctions{
		AuthnSignFunc:           signFn,
		AuthnCertFunc:           certFn,
		ClientAssertionSignFunc: signFn,
		ClientAssertionCertFunc: certFn,
		ProvidePN:               providePN,
		ProvideHCV:              provideHCV,
	}, nil
}
