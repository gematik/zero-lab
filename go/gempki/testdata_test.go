package gempki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Brainpool TI certificate fixtures.
// Source: gematik erp-e2e-testsuite (TEST-ONLY, not production).
// Reused from the sibling brainpool package's test fixtures so we exercise
// real-world TI cert formats (SMC-B leaf signed by an intermediate CA signed
// by GEM.RCA5, all Brainpool P-256r1).

// fixtureBrainpoolRCA5PEM — self-signed root, brainpoolP256r1.
const fixtureBrainpoolRCA5PEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

// fixtureBrainpoolSMCBCA5PEM — intermediate CA signed by RCA5, brainpoolP256r1.
const fixtureBrainpoolSMCBCA5PEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

// fixtureBrainpoolSMCBEEPEM — SMC-B end-entity cert (Arztpraxis Bernd
// Rosenstrauch), signed by SMCB-CA5, brainpoolP256r1.
const fixtureBrainpoolSMCBEEPEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

// fixtureBrainpoolEEDER returns the DER bytes of the SMC-B EE cert.
func fixtureBrainpoolEEDER(t *testing.T) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NotNil(t, block, "fixture PEM must decode")
	return block.Bytes
}

// makeSelfSignedECDSA generates a self-signed cert on the given curve using
// the standard library. Used for NIST and policy-rejection paths.
func makeSelfSignedECDSA(t *testing.T, curve elliptic.Curve, cn string) (certDER []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	return der, k
}

// makeSelfSignedRSA generates a self-signed RSA cert solely so we can test
// that gempki rejects it loudly. RSA must never validate through this
// library — that's a TI-PKI policy invariant.
func makeSelfSignedRSA(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	return der
}
