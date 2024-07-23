package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	"github.com/gematik/zero-lab/go/libzero/ca"
	"github.com/google/go-attestation/attest"
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

// Test RSA Certificate signing
func TestRSACertificateSigning(t *testing.T) {
	ak := "AAEACwAFBHIAAAAQABQACwgAAAAAAAEAue7j2pNtfRX0IK7GqE2xEDvWTFZG6O9H2i7arY+j2Fz8tZuBva61navtbEiWudlPw9ViEvhKwycZnLEQYadeTJ0nNDJVPWnlZgbhTDP+mxvZYVheAZDb+/iSg20+71HCBcvjHttrTrF5h8BU9rvmcBv03UBGvxlLqzzKhv6q/swBes+4cIV18mchuGfDwBWwshfKhu/VFsyA1UK4XePjX2nZGLwzFKvaWluk/dF495xkHQVajdsdWkCmppethDi0okyfq2ezXPjldsLQVzB9Ntijx/k5uuAV5s6y7usVhHUQNqj5tesjJXSklFwaFscj98QFvIc/YrsejoMwaxbLkQ=="
	akBytes, err := base64.StdEncoding.DecodeString(ak)
	if err != nil {
		t.Fatalf("failed to decode AK: %s", err)
	}
	akPublic, err := attest.ParseAKPublic(attest.TPMVersion20, akBytes)
	if err != nil {
		t.Fatalf("failed to parse AK public: %s", err)
	}
	t.Log("AK Public Key ", "key_type", reflect.TypeOf(akPublic.Public))

	ca, _ := ca.NewRandomMockCA()

	cert, err := ca.CertifyPublicKey(akPublic.Public, pkix.Name{CommonName: "Test Certificate"})
	if err != nil {
		t.Fatalf("failed to sign certificate: %s", err)
	}
	t.Log("Certificate", "subject", cert.Subject.String())

	keyBytes, err := x509.MarshalPKIXPublicKey(akPublic.Public)
	if err != nil {
		t.Fatalf("failed to marshal public key: %s", err)
	}

	akPuk, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %s", err)
	}

	cert, err = ca.CertifyPublicKey(akPuk, pkix.Name{CommonName: "Test Certificate #2"})
	if err != nil {
		t.Fatalf("failed to sign certificate: %s", err)
	}

	t.Log("Certificate", "subject", cert.Subject.String())

}
