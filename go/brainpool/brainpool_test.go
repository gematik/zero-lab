package brainpool_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/stretchr/testify/assert"
)

// sample keys and certificates from https://github.com/gematik/erp-e2e-testsuite
var testKeyBytes = []byte(`-----BEGIN EC PRIVATE KEY-----
MHgCAQEEID0gGM/y+gETNO9kFWY6vELk9rjq2H/tuZogskG/rpB8oAsGCSskAwMC
CAEBB6FEA0IABGc0iasne1f/tcuTSw4CiRfxZ3LvLsQDuMmbqTO5CuOsXND+n8fV
Q3zyzOv7imMbR7nqdiEFGAHtGNznbsLrU80=
-----END EC PRIVATE KEY-----`)

var testKeyPkcs8Bytes = []byte(`-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEID0gGM/y+gETNO9k
FWY6vELk9rjq2H/tuZogskG/rpB8oUQDQgAEZzSJqyd7V/+1y5NLDgKJF/Fncu8u
xAO4yZupM7kK46xc0P6fx9VDfPLM6/uKYxtHuep2IQUYAe0Y3OduwutTzQ==
-----END PRIVATE KEY-----`)

var testCertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIDeDCCAx6gAwIBAgIHArLLcBI3KDAKBggqhkjOPQQDAjCBmjELMAkGA1UEBhMC
REUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxSDBGBgNVBAsMP0lu
c3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIgVGVsZW1hdGlr
aW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLlNNQ0ItQ0E1MSBURVNULU9OTFkw
HhcNMjMxMTA5MjMwMDAwWhcNMjgxMTA5MjI1OTU5WjCBhDELMAkGA1UEBhMCREUx
HDAaBgNVBAoMEzEwMjMxMDgwMSBOT1QtVkFMSUQxFTATBgNVBAQMDFJvc2Vuc3Ry
YXVjaDEOMAwGA1UEKgwFQmVybmQxMDAuBgNVBAMMJ0FyenRwcmF4aXMgQmVybmQg
Um9zZW5zdHJhdWNoIFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNC
AARnNImrJ3tX/7XLk0sOAokX8Wdy7y7EA7jJm6kzuQrjrFzQ/p/H1UN88szr+4pj
G0e56nYhBRgB7Rjc527C61PNo4IBYDCCAVwwLAYDVR0fBCUwIzAhoB+gHYYbaHR0
cDovL2VoY2EuZ2VtYXRpay5kZS9jcmwvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUshKrzlr5DNSiNzsEXWLuScZAN2wwDAYD
VR0TAQH/BAIwADAfBgNVHSMEGDAWgBQGmOkCVf/Jn1yjZQ7xXeIg9YT7kzA7Bggr
BgEFBQcBAQQvMC0wKwYIKwYBBQUHMAGGH2h0dHA6Ly9laGNhLmdlbWF0aWsuZGUv
ZWNjLW9jc3AwWgYFKyQIAwMEUTBPME0wSzBJMEcwFgwUQmV0cmllYnNzdMOkdHRl
IEFyenQwCQYHKoIUAEwEMhMiMS0yLUFSWlRQUkFYSVMtQmVybmRSb3NlbnN0cmF1
Y2gwMTAgBgNVHSAEGTAXMAoGCCqCFABMBIEjMAkGByqCFABMBE0wCgYIKoZIzj0E
AwIDSAAwRQIgWlSdCIw6Z6alM+dGnA4vfkxDoViIqJMw/PH4U0VUmNsCIQCcX9UW
JnSDBKGp4nZTcuozRPsJK47cBkil0x6Zrkoxkg==
-----END CERTIFICATE-----`)

var testCaCertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIDCTCCAq+gAwIBAgIBFTAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAd
BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxl
IFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdF
TS5SQ0E1IFRFU1QtT05MWTAeFw0yMTExMDgxNDM1MjBaFw0yOTExMDYxNDM1MTla
MIGaMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJ
RDFIMEYGA1UECww/SW5zdGl0dXRpb24gZGVzIEdlc3VuZGhlaXRzd2VzZW5zLUNB
IGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMSAwHgYDVQQDDBdHRU0uU01DQi1D
QTUxIFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNCAARyL9gf/BnU
XVDBnaMY+8ekrslFzS6kXZ83xnxcBWFQVqmWUMNbCLFO4JaFBLqQMyg1QOh6EIhm
8S2JD4BblLHFo4H7MIH4MB0GA1UdDgQWBBQGmOkCVf/Jn1yjZQ7xXeIg9YT7kzAf
BgNVHSMEGDAWgBThreAH/NIgeST03Je9MmTNaxSFCTBKBggrBgEFBQcBAQQ+MDww
OgYIKwYBBQUHMAGGLmh0dHA6Ly9vY3NwLXRlc3RyZWYucm9vdC1jYS50aS1kaWVu
c3RlLmRlL29jc3AwDgYDVR0PAQH/BAQDAgEGMEYGA1UdIAQ/MD0wOwYIKoIUAEwE
gSMwLzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5nZW1hdGlrLmRlL2dvL3BvbGlj
aWVzMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0EAwIDSAAwRQIgDvK1qhUF
h2gLvPo+A5v8kufzXbix/F/vMFAyHKFZp6ECIQCPbcZbur8+zM+3vdidr1KH+x7O
M2VUJBbT0gYAHiqjAA==
-----END CERTIFICATE-----`)

var testRootCaCertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIICyzCCAnKgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAd
BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxl
IFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdF
TS5SQ0E1IFRFU1QtT05MWTAeFw0yMTA3MjIxMjU0MTFaFw0zMTA3MjAxMjU0MTFa
MIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJ
RDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFz
dHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTUgVEVTVC1PTkxZMFowFAYHKoZIzj0C
AQYJKyQDAwIIAQEHA0IABJukjjeYlo6B3WTeNVof861qQRIa3ZcAkUyj1zMER6I+
aley7K/U1XCFQ72ADk9qoRAYNspYA1dVQiFsXML32PWjgdcwgdQwHQYDVR0OBBYE
FOGt4Af80iB5JPTcl70yZM1rFIUJMEoGCCsGAQUFBwEBBD4wPDA6BggrBgEFBQcw
AYYuaHR0cDovL29jc3AtdGVzdHJlZi5yb290LWNhLnRpLWRpZW5zdGUuZGUvb2Nz
cDAOBgNVHQ8BAf8EBAMCAQYwRgYDVR0gBD8wPTA7BggqghQATASBIzAvMC0GCCsG
AQUFBwIBFiFodHRwOi8vd3d3LmdlbWF0aWsuZGUvZ28vcG9saWNpZXMwDwYDVR0T
AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAGnycg02dlaa1JGjN2g2NGc28j
j4yuHQZrOb0yDWrgVQIgBRqGkgNF8R2HTjHZpW/ImKbvHoO6iV1AwzfFl1uzdG0=
-----END CERTIFICATE-----`)

func TestSignature(t *testing.T) {
	priv, err := parsePEMKey(testKeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test")
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := parsePEMCert(testCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("failed to convert public key to ECDSA public key")
	}

	if !ecdsa.Verify(ecdsaPubKey, msg, r, s) {
		t.Fatal("signature didn't verify.")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	_, err := brainpool.ParsePrivateKeyPEM(testKeyBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
}

func TestParsePrivateKeyPkcs8PEM(t *testing.T) {
	_, err := brainpool.ParsePrivateKeyPEM(testKeyPkcs8Bytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
}

func parsePEMKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return brainpool.ParseECPrivateKey(pemBlock.Bytes)
}

func parsePEMCert(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return brainpool.ParseCertificate(pemBlock.Bytes)
}

func TestParseCertificatePEM(t *testing.T) {
	cert, err := brainpool.ParseCertificatePEM(testCertBytes)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}
	assert.NotNil(t, cert)
}

func TestParseCertificateFields(t *testing.T) {
	cert, err := brainpool.ParseCertificatePEM(testCertBytes)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}

	// Assert Raw fields are not empty
	assert.NotEmpty(t, cert.Raw, "Raw certificate should not be empty")
	assert.Greater(t, len(cert.Raw), 0, "Raw certificate should have meaningful length")

	assert.NotEmpty(t, cert.RawTBSCertificate, "RawTBSCertificate should not be empty")
	assert.Greater(t, len(cert.RawTBSCertificate), 0, "RawTBSCertificate should have meaningful length")

	assert.NotEmpty(t, cert.RawSubjectPublicKeyInfo, "RawSubjectPublicKeyInfo should not be empty")
	assert.Greater(t, len(cert.RawSubjectPublicKeyInfo), 0, "RawSubjectPublicKeyInfo should have meaningful length")

	assert.NotEmpty(t, cert.RawSubject, "RawSubject should not be empty")
	assert.Greater(t, len(cert.RawSubject), 0, "RawSubject should have meaningful length")

	assert.NotEmpty(t, cert.RawIssuer, "RawIssuer should not be empty")
	assert.Greater(t, len(cert.RawIssuer), 0, "RawIssuer should have meaningful length")

	// Assert Signature fields
	assert.NotEmpty(t, cert.Signature, "Signature should not be empty")
	assert.Greater(t, len(cert.Signature), 0, "Signature should have meaningful length")
	assert.NotEqual(t, x509.UnknownSignatureAlgorithm, cert.SignatureAlgorithm, "SignatureAlgorithm should be known")

	// Assert PublicKey fields
	assert.NotEqual(t, x509.UnknownPublicKeyAlgorithm, cert.PublicKeyAlgorithm, "PublicKeyAlgorithm should be known")
	assert.NotNil(t, cert.PublicKey, "PublicKey should not be nil")

	// Assert Version
	assert.Greater(t, cert.Version, 0, "Version should be greater than 0")
	assert.LessOrEqual(t, cert.Version, 3, "Version should be <= 3")

	// Assert SerialNumber
	assert.NotNil(t, cert.SerialNumber, "SerialNumber should not be nil")
	assert.Greater(t, cert.SerialNumber.Sign(), 0, "SerialNumber should be positive")

	// Assert Issuer
	assert.NotEmpty(t, cert.Issuer.String(), "Issuer should not be empty")
	assert.Equal(t, "Institution des Gesundheitswesens-CA der Telematikinfrastruktur", cert.Issuer.OrganizationalUnit[0], "Issuer OrganizationalUnit mismatch")

	// Assert Subject
	assert.NotEmpty(t, cert.Subject.String(), "Subject should not be empty")
	assert.Equal(t, "Arztpraxis Bernd Rosenstrauch TEST-ONLY", cert.Subject.CommonName, "Subject CommonName mismatch")

	// Assert Validity bounds
	assert.False(t, cert.NotBefore.IsZero(), "NotBefore should not be zero")
	assert.False(t, cert.NotAfter.IsZero(), "NotAfter should not be zero")
	assert.True(t, cert.NotAfter.After(cert.NotBefore), "NotAfter should be after NotBefore")

	// test extensions
	assert.Greater(t, len(cert.Extensions), 0, "Extensions should not be empty")

	// test key usage
	assert.Greater(t, cert.KeyUsage, 0, "KeyUsage should be set")
	assert.True(t, cert.KeyUsage&x509.KeyUsageDigitalSignature != 0, "KeyUsage should contain DigitalSignature")

	// test extended key usage
	assert.Greater(t, len(cert.ExtKeyUsage), 0, "ExtKeyUsage should not be empty")
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth, "ExtKeyUsage should contain ClientAuth")

	// skid
	assert.Greater(t, len(cert.SubjectKeyId), 0, "SubjectKeyId should not be empty")
	assert.Equal(t, []byte{0xB2, 0x12, 0xAB, 0xCE, 0x5A, 0xF9, 0x0C, 0xD4, 0xA2, 0x37, 0x3B, 0x04, 0x5D, 0x62, 0xEE, 0x49, 0xC6, 0x40, 0x37, 0x6C}, cert.SubjectKeyId, "SubjectKeyId mismatch")

	// basic constraints
	assert.True(t, cert.IsCA == false, "IsCA should be false")
	assert.Equal(t, 0, cert.MaxPathLen, "MaxPathLen should be 0")

	// ocsp
	assert.Greater(t, len(cert.OCSPServer), 0, "OCSPServer should not be empty")
	assert.Equal(t, "http://ehca.gematik.de/ecc-ocsp", cert.OCSPServer[0], "OCSPServer mismatch")

	// must contail policy identifiers 1.2.276.0.76.4.163 and 1.2.276.0.76.4.77
	assert.Greater(t, len(cert.PolicyIdentifiers), 0, "PolicyIdentifiers should not be empty")
	assert.Contains(t, cert.PolicyIdentifiers, asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 163}, "PolicyIdentifiers should contain 1.2.276.0.76.4.163")
	assert.Contains(t, cert.PolicyIdentifiers, asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 77}, "PolicyIdentifiers should contain 1.2.276.0.76.4.77")

}

func TestParseCACertificatePEM(t *testing.T) {
	cert, err := brainpool.ParseCertificatePEM(testCaCertBytes)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}
	assert.NotNil(t, cert)

	assert.True(t, cert.IsCA, "IsCA should be true for CA certificate")
	assert.Equal(t, 0, cert.MaxPathLen, "MaxPathLen should be 0 for CA certificate")

	// assert brainpool curve
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("failed to convert public key to ECDSA public key")
	}
	curve := cert.PublicKey.(*ecdsa.PublicKey).Curve
	assert.Equal(t, "brainpoolP256r1", curve.Params().Name, "Expected brainpoolP256r1 curve for CA certificate")

	// assert key usage
	assert.Greater(t, cert.KeyUsage, 0, "KeyUsage should be set for CA certificate")
	assert.True(t, cert.KeyUsage&x509.KeyUsageCertSign != 0, "KeyUsage should contain CertSign for CA certificate")
	assert.True(t, cert.KeyUsage&x509.KeyUsageCRLSign != 0, "KeyUsage should contain CRLSign for CA certificate")
}

func TestParseRootCACertificatePEM(t *testing.T) {
	cert, err := brainpool.ParseCertificatePEM(testRootCaCertBytes)
	if err != nil {
		t.Fatalf("ParseCertificatePEM failed: %v", err)
	}
	assert.NotNil(t, cert)

	assert.True(t, cert.IsCA, "IsCA should be true for Root CA certificate")
	//assert.Equal(t, 1, cert.MaxPathLen, "MaxPathLen should be 1 for Root CA certificate")

	// assert brainpool curve
	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("failed to convert public key to ECDSA public key")
	}
	curve := cert.PublicKey.(*ecdsa.PublicKey).Curve
	assert.Equal(t, "brainpoolP256r1", curve.Params().Name, "Expected brainpoolP256r1 curve for Root CA certificate")

	// assert key usage
	assert.Greater(t, cert.KeyUsage, 0, "KeyUsage should be set for Root CA certificate")
	assert.True(t, cert.KeyUsage&x509.KeyUsageCertSign != 0, "KeyUsage should contain CertSign for Root CA certificate")
	assert.True(t, cert.KeyUsage&x509.KeyUsageCRLSign != 0, "KeyUsage should contain CRLSign for Root CA certificate")
}

func TestNilInput(t *testing.T) {
	_, err := brainpool.ParseCertificatePEM(nil)
	if err == nil {
		t.Fatalf("Expected error for nil input in ParseCertificatePEM, got nil")
	}

	_, err = brainpool.ParsePrivateKeyPEM(nil)
	if err == nil {
		t.Fatalf("Expected error for nil input in ParsePrivateKeyPEM, got nil")
	}

	_, err = brainpool.ParseCertificate(nil)
	if err == nil {
		t.Fatalf("Expected error for nil input in ParseCertificate, got nil")
	}
}

func TestSubjectParsing(t *testing.T) {
	certBase64 := `MIIDijCCAzGgAwIBAgIHAK4aqPhmlDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNjA0BgNVBAsMLVF1YWxpZml6aWVydGVyIFZEQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLkhCQS1xQ0E1MSBURVNULU9OTFkwHhcNMjQxMjAzMDAwMDAwWhcNMjkxMjAzMjM1OTU5WjBzMQswCQYDVQQGEwJERTFkMA4GA1UEKgwHVWxscmljaDARBgNVBAQMCkFuZ2VybcOkbm4wGwYDVQQFExQ4MDI3Njg4MzExMDAwMDE2Mzk3NDAiBgNVBAMMG1VsbHJpY2ggQW5nZXJtw6RublRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNCAARZ3Wv87oBjWg/plcaHVtMMJIyhxxSBJhtGycd/OuDxvRDf48s+/5+/UJOuJMbFzuJYcuJKzNplZr6XqCqICYNbo4IBlzCCAZMwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYBATAIBgYEAI5GAQQwGwYJKwYBBAHAbQMFBA4wDAYKKwYBBAHAbQMFATAMBgNVHRMBAf8EAjAAMDkGA1UdIAQyMDAwCQYHKoIUAEwESDAJBgcEAIvsQAECMAoGCCqCFABMBIERMAwGCisGAQQBgs0zAQEwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzABhiBodHRwOi8vZWhjYS5nZW1hdGlrLmRlL2VjYy1xb2NzcDAOBgNVHQ8BAf8EBAMCBkAwHQYDVR0OBBYEFJjLsEp9jJQWFCgq0sZxS4SnU+RoMB8GA1UdIwQYMBaAFFztN5TdWlaBgLcpVEEcxrkFvuu8MHkGBSskCAMDBHAwbqQoMCYxCzAJBgNVBAYTAkRFMRcwFQYDVQQKDA5nZW1hdGlrIEJlcmxpbjBCMEAwPjA8MA4MDMOEcnp0aW4vQXJ6dDAJBgcqghQATAQeEx8xLUhCQS1UZXN0a2FydGUtODgzMTEwMDAwMTYzOTc0MAoGCCqGSM49BAMCA0cAMEQCIHijw1NSTSQYrZ7vWzCOOl5NawkcsWof3t6vN7uZTZguAiAyZW8q1tSOzdQnMUH03mAbRdiYlQ6AkhE/UemL18v/7Q==`
	certBytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		t.Fatalf("Failed to decode base64 certificate: %v", err)
	}
	cert, err := brainpool.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	assert.Equal(t, []string{"DE"}, cert.Subject.Country)
	assert.Equal(t, "Ullrich Angerm\u00e4nnTEST-ONLY", cert.Subject.CommonName)
	assert.Equal(t, "80276883110000163974", cert.Subject.SerialNumber)

	// GivenName (2.5.4.42) and Surname (2.5.4.4) are stored in Names
	var givenName, surname string
	for _, name := range cert.Subject.Names {
		switch {
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 42}):
			givenName = name.Value.(string)
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 4}):
			surname = name.Value.(string)
		}
	}
	assert.Equal(t, "Ullrich", givenName)
	assert.Equal(t, "Angerm\u00e4nn", surname)
}

func TestCrossCertificateVerification(t *testing.T) {
	var anchorPEM = `-----BEGIN CERTIFICATE-----
MIICzTCCAnOgAwIBAgIBATAKBggqhkjOPQQDAjCBgjELMAkGA1UEBhMCREUxHzAd
BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxl
IFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxHDAaBgNVBAMME0dF
TS5SQ0ExMCBURVNULU9OTFkwHhcNMjUwNTA4MTIwODA0WhcNMzUwNTA2MTIwODA0
WjCBgjELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFM
SUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJh
c3RydWt0dXIxHDAaBgNVBAMME0dFTS5SQ0ExMCBURVNULU9OTFkwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAATnZExIrTwptz9EJUY/T9n8n10aY++5T2JQKarANPCm
PSo9nv2vwvePXbe7tB+6QQj0jwDniWrOwd5PtTFjMXDio4HXMIHUMB0GA1UdDgQW
BBS0QNvJwfb7eHYiztH7eSbzWIqRCjBKBggrBgEFBQcBAQQ+MDwwOgYIKwYBBQUH
MAGGLmh0dHA6Ly9vY3NwLXRlc3RyZWYucm9vdC1jYS50aS1kaWVuc3RlLmRlL29j
c3AwDgYDVR0PAQH/BAQDAgEGMEYGA1UdIAQ/MD0wOwYIKoIUAEwEgSMwLzAtBggr
BgEFBQcCARYhaHR0cDovL3d3dy5nZW1hdGlrLmRlL2dvL3BvbGljaWVzMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKmNBIGUeu2PFH6hD2mGyGSx
rvVY8gsiooXO+gwODNfiAiByRfTY1l2QB3UGWrgyDZs8SAkKPAltj0zNKuuhj8uF
DQ==
-----END CERTIFICATE-----`

	var crossCertPEM = `-----BEGIN CERTIFICATE-----
MIIC7jCCApWgAwIBAgIBBjAKBggqhkjOPQQDAjCBgjELMAkGA1UEBhMCREUxHzAd
BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxl
IFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxHDAaBgNVBAMME0dF
TS5SQ0ExMCBURVNULU9OTFkwHhcNMjUwNzMxMDkzNzU0WhcNMzUwNTA2MDkzNzUz
WjCBgjELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFM
SUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJh
c3RydWt0dXIxHDAaBgNVBAMME0dFTS5SQ0ExMSBURVNULU9OTFkwWjAUBgcqhkjO
PQIBBgkrJAMDAggBAQcDQgAEM+tXRqOS0Fak7/qZdiZQwlKmm+3OspytaRA1OdrO
4sUO3JoeLSTUDUAJoOtchwDwiq9jrbsVbaQDU4VqB3BcQKOB+DCB9TAdBgNVHQ4E
FgQUAgoWJunzX0JiKe6ckosFM5fechQwHwYDVR0jBBgwFoAUtEDbycH2+3h2Is7R
+3km81iKkQowSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzABhi5odHRwOi8vb2Nz
cC10ZXN0cmVmLnJvb3QtY2EudGktZGllbnN0ZS5kZS9vY3NwMA4GA1UdDwEB/wQE
AwIBBjBGBgNVHSAEPzA9MDsGCCqCFABMBIEjMC8wLQYIKwYBBQUHAgEWIWh0dHA6
Ly93d3cuZ2VtYXRpay5kZS9nby9wb2xpY2llczAPBgNVHRMBAf8EBTADAQH/MAoG
CCqGSM49BAMCA0cAMEQCIGJzLNFtIM9MMMkFWkUv+Z5xzhCmR/CCjIbzwQCbkVgJ
AiA8IFHJslZ76EpSSgKQkDdsFTOHeDXzjeDd+xBcm5IrIg==
-----END CERTIFICATE-----`

	anchorCert, err := brainpool.ParseCertificatePEM([]byte(anchorPEM))
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	crossCert, err := brainpool.ParseCertificatePEM([]byte(crossCertPEM))
	if err != nil {
		t.Fatalf("Failed to parse cross certificate: %v", err)
	}

	assert.Equal(t, 665, len(crossCert.RawTBSCertificate), "Unexpected length of RawTBSCertificate in cross certificate")

	err = crossCert.CheckSignatureFrom(anchorCert)
	if err != nil {
		t.Fatalf("Cross certificate signature verification failed: %v", err)
	}
}
