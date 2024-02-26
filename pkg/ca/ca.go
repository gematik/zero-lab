package ca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// Simple interface for a certificate authority
type CertificateAuthority interface {
	IssuerCertificate() *x509.Certificate
	SignCertificateRequest(csr *x509.CertificateRequest, subject pkix.Name) (*x509.Certificate, error)
}

// Encodes a X509 certificate to PEM format
func EncodeCertToPEM(cert *x509.Certificate) (string, error) {
	certPem := new(bytes.Buffer)
	err := pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return "", err
	}
	return certPem.String(), nil
}
