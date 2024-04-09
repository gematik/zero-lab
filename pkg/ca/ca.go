package ca

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
)

// id-isismtt-at-additionalInformation OBJECT IDENTIFIER ::= {id-isismtt-at 15}
var OIDAdditionalInformation = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 15}

type SigningOption func(*x509.Certificate) error

func WithAdditionalInformation(ai interface{}) SigningOption {
	return func(cert *x509.Certificate) error {
		// Encode the additional information as JSON
		aiBytes, err := json.Marshal(ai)
		if err != nil {
			return err
		}

		// Add the additional information as an extension
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    OIDAdditionalInformation,
			Value: aiBytes,
		})
		return nil
	}

}

// Simple interface for a certificate authority
type CertificateAuthority interface {
	IssuerCertificate() *x509.Certificate
	SignCertificateRequest(csr *x509.CertificateRequest, subject pkix.Name, ops ...SigningOption) (*x509.Certificate, error)
	CertifyPublicKey(pubKey crypto.PublicKey, subject pkix.Name, ops ...SigningOption) (*x509.Certificate, error)
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
