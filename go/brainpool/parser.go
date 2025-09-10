package brainpool

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}
	if pemBlock.Type == "PRIVATE KEY" {
		// convert pkc8 to der
		key, err := ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil
		}
		return ecdsaKey, nil
	} else if pemBlock.Type == "EC PRIVATE KEY" {
		return ParseECPrivateKey(pemBlock.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM block type: %s", pemBlock.Type)
}

func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return ParseCertificate(pemBlock.Bytes)
}
