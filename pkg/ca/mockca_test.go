package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"reflect"
	"testing"

	"github.com/gematik/zero-lab/pkg/ca"
)

func TestCertificateExtension(t *testing.T) {
	t.Log("TestCertificateExtension")
	testCA, _ := ca.NewMockCA(
		pkix.Name{
			CommonName: "Test CA",
		},
	)
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Test Certificate"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	// step: generate the csr request
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keyPair)
	if err != nil {
		t.Fatalf("failed to create csr request: %s", err)
	}

	csrCertificate, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse csr request: %s", err)
	}

	type additionalInformation struct {
		Owner             string `json:"owner"`
		AttestationMethod string `json:"attestation_method"`
	}

	cert, _ := testCA.SignCertificateRequest(
		csrCertificate,
		csrTemplate.Subject,
		ca.WithAdditionalInformation(&additionalInformation{
			Owner:             "Test Owner",
			AttestationMethod: "Test Attestation Method",
		}),
	)

	certPEM, _ := ca.EncodeCertToPEM(cert)
	t.Log(certPEM)

	extensionPresent := false
	for _, ext := range cert.Extensions {
		if reflect.DeepEqual(ext.Id, ca.OIDAdditionalInformation) {
			extensionPresent = true
		}
	}

	if !extensionPresent {
		t.Error("expected extension to be present")
	}

	// write the certificate to disk /tmp/cert.pem
	os.WriteFile("/tmp/cert.pem", []byte(certPEM), 0644)

}
