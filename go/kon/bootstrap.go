package kon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// loads the trust store form PEM file containing all trusted certificates
func LoadTrustStore(path string) (*x509.CertPool, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trust store: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certPEM) {
		return nil, fmt.Errorf("appending certs from PEM: %w", err)
	}

	return certPool, nil
}

// Load a cerver certificate from TLS endpoint
func LoadServerCertificate(addr string) (*x509.Certificate, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}

	certs := c.ConnectionState().PeerCertificates

	cert := certs[0]

	c.Close()

	return cert, nil
}

// save certificate to PEM file
func SaveCertificates(path string, certs ...*x509.Certificate) error {
	pemFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer pemFile.Close()

	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(pemFile, pemBlock); err != nil {
			return fmt.Errorf("encoding PEM: %w", err)
		}
	}
	return nil

}
