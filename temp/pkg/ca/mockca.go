package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/segmentio/ksuid"
)

type mockCertificateAuthority struct {
	Certificate *x509.Certificate
	prk         *ecdsa.PrivateKey
}

func NewRandomMockCA() (CertificateAuthority, error) {
	issuer := pkix.Name{
		CommonName: ksuid.New().String(),
	}
	return NewMockCA(issuer)
}

func NewMockCA(issuer pkix.Name) (CertificateAuthority, error) {
	sn, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return nil, err
	}
	caCrt := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               issuer,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * 30 * 6 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	signedBytes, err := x509.CreateCertificate(rand.Reader, caCrt, caCrt, &caPrk.PublicKey, caPrk)
	if err != nil {
		return nil, err
	}

	caCrt, err = x509.ParseCertificate(signedBytes)
	if err != nil {
		return nil, err
	}

	return &mockCertificateAuthority{
		Certificate: caCrt,
		prk:         caPrk,
	}, nil

}

func (ca *mockCertificateAuthority) IssuerCertificate() *x509.Certificate {
	return ca.Certificate
}

func (ca *mockCertificateAuthority) SignCertificateRequest(csr *x509.CertificateRequest, subject pkix.Name, opts ...SigningOption) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	return ca.createCertificate(csr.PublicKey, csr.PublicKeyAlgorithm, subject, opts...)
}

func (ca *mockCertificateAuthority) createCertificate(
	publicKey crypto.PublicKey,
	publicKeyAlgorithm x509.PublicKeyAlgorithm,
	subject pkix.Name,
	opts ...SigningOption) (*x509.Certificate, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("unable to generate serial number: %w", err)
	}

	crtTemplate := x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,

		PublicKeyAlgorithm: publicKeyAlgorithm,
		PublicKey:          publicKey,

		SerialNumber: serialNumber,
		Issuer:       ca.Certificate.Subject,
		Subject:      subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, opt := range opts {
		if err := opt(&crtTemplate); err != nil {
			return nil, fmt.Errorf("unable to apply signing option: %w", err)
		}
	}

	crtRaw, err := x509.CreateCertificate(rand.Reader, &crtTemplate, ca.Certificate, publicKey, ca.prk)
	if err != nil {
		return nil, fmt.Errorf("unable to sign client certificate: %w", err)
	}

	crt, err := x509.ParseCertificate(crtRaw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client certificate: %w", err)
	}

	return crt, nil

}

func (ca *mockCertificateAuthority) CertifyPublicKey(pubKey crypto.PublicKey, subject pkix.Name, opts ...SigningOption) (*x509.Certificate, error) {
	var alg x509.PublicKeyAlgorithm
	switch pubKey.(type) {
	case *ecdsa.PublicKey:
		alg = x509.ECDSA
	case *rsa.PublicKey:
		alg = x509.RSA
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
	slog.Info("Certifying public key", "subject", subject, "algorithm", alg)
	return ca.createCertificate(pubKey, alg, subject, opts...)
}
