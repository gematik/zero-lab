package asl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func createMockCertData() (*CertData, error) {
	// Generate CA private key
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA private key: %w", err)
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Mock CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	// Generate EE private key
	eePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating EE private key: %w", err)
	}

	// Create EE certificate template
	eeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Mock EE"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// Sign the EE certificate with the CA certificate
	eeCertDER, err := x509.CreateCertificate(rand.Reader, eeTemplate, caCert, &eePrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("creating EE certificate: %w", err)
	}

	// Parse the EE certificate
	eeCert, err := x509.ParseCertificate(eeCertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing EE certificate: %w", err)
	}

	// Return the CertData
	return &CertData{
		CACert:   caCert,
		Cert:     eeCert,
		RCAChain: []*x509.Certificate{caCert},
	}, nil
}
