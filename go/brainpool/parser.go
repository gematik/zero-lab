package brainpool

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

func ParsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return ParseECPrivateKey(pemBlock.Bytes)
}

func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return ParseCertificate(pemBlock.Bytes)
}
