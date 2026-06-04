package gempki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileSMCBAuth_AcceptsBrainpoolFixtureCert(t *testing.T) {
	t.Parallel()
	rca5, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore(rca5)
	require.NoError(t, err)

	v := gempki.ProfileSMCBAuth(ts)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)

	pemAll := []byte(fixtureBrainpoolSMCBEEPEM + "\n" +
		fixtureBrainpoolSMCBCA51PEM)
	result, err := v.ValidatePEM(t.Context(), pemAll)
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestProfileSMCBAuth_RejectsHBARoleOID(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	// EE asserting an HBA person OID, not an SMC-B institution OID.
	admExt, err := testca.AdmissionExtension(
		"Arzt", asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 30}, "test-reg",
	)
	require.NoError(t, err)
	ee := customEE(t, pki, testca.CertOptions{
		KeyUsage:            x509.KeyUsageDigitalSignature,
		ExtKeyUsage:         []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CertificatePolicies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
		ExtraExtensions:     []pkix.Extension{admExt},
	})

	v := gempki.ProfileSMCBAuth(ts)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeRoleOIDMissing))
}

func TestProfileQES_AcceptsHBAQESCert(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	admExt, err := testca.AdmissionExtension(
		"Arzt", asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, 30}, "test-arzt-hba",
	)
	require.NoError(t, err)

	opts := testca.CertOptions{
		KeyUsage: x509.KeyUsageContentCommitment, // QES = nonRepudiation
		CertificatePolicies: []asn1.ObjectIdentifier{
			gempki.OIDPolicyHbaCP, gempki.OIDPolicyGemOrCP,
		},
		ExtraExtensions: []pkix.Extension{admExt},
	}
	opts.Serial = big.NewInt(time.Now().UnixNano())
	opts.NotBefore = time.Now().Add(-time.Hour)
	opts.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := testca.CreateCertificate(opts, &pki.EEArzt.Key.PublicKey, pki.SubCAHBA.Cert, pki.SubCAHBA.Key)
	require.NoError(t, err)
	ee, err := gempki.ParseCertificate(der)
	require.NoError(t, err)

	v := gempki.ProfileQES(ts)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestProfileKomponente_AcceptsServerAuthEE(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})

	// Build a NIST EE under SubCAKomp asserting serverAuth + the required policy.
	ee := customNISTEE(t, pki, testca.CertOptions{
		KeyUsage:            x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:         []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CertificatePolicies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
		DNSNames:            []string{"komp.test.invalid"},
	})

	v := gempki.ProfileKomponente(ts)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAKomp.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

// customNISTEE — sibling of customEE but issued under SubCAKomp (NIST).
func customNISTEE(t *testing.T, pki *testca.TestPKI, opts testca.CertOptions) *x509.Certificate {
	t.Helper()
	opts.Subject.CommonName = "nist-komp-ee"
	opts.Subject.Country = []string{"DE"}
	opts.Serial = big.NewInt(time.Now().UnixNano())
	opts.NotBefore = time.Now().Add(-time.Hour)
	opts.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := testca.CreateCertificate(opts, &pki.EEZeta.Key.PublicKey, pki.SubCAKomp.Cert, pki.SubCAKomp.Key)
	require.NoError(t, err)
	cert, err := gempki.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestWithOCSPNetworkChecker_UsesProvidedHTTPClient(t *testing.T) {
	t.Parallel()
	// Confirm the convenience option installs an OCSPChecker that respects
	// the provided http.Client — a minimal wiring smoke test, no real OCSP.
	called := atomic.Int32{}
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called.Add(1)
			return nil, http.ErrUseLastResponse
		}),
	}

	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithOCSPNetworkChecker(client, "http://example.invalid/ocsp"),
		gempki.WithRevocationMode(gempki.RevocationModeSoftFail), // tolerate the OCSP error
	)
	_, err = v.Validate(t.Context(), []*x509.Certificate{pki.EEZeta.Cert, pki.SubCAKomp.Cert})
	require.NoError(t, err)
	assert.Positive(t, called.Load(), "custom http.Client must be used by OCSPChecker")
}
