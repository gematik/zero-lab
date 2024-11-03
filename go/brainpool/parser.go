package brainpool

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/spilikin/go-brainpool"
)

func ParsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return brainpool.ParseECPrivateKey(pemBlock.Bytes)
}

func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return brainpool.ParseCertificate(pemBlock.Bytes)
}
