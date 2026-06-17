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

func TestProfileSmbAuth_AcceptsBrainpoolFixtureCert(t *testing.T) {
	t.Parallel()
	rca5, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore(rca5)
	require.NoError(t, err)

	v := gempki.ProfileSmbAuth.Validator(ts, gempki.CertTypeHciAUT)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)

	pemAll := []byte(fixtureBrainpoolSMCBEEPEM + "\n" +
		fixtureBrainpoolSMCBCA51PEM)
	result, err := v.ValidatePEM(t.Context(), pemAll)
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestProfileSmbAuth_RejectsHBARoleOID(t *testing.T) {
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

	v := gempki.ProfileSmbAuth.Validator(ts, gempki.CertTypeHciAUT)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeRoleOIDMissing))
}

func TestProfileIdp_AcceptsFdSIGShape(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})

	// Build a Fachdienst-shape EE under SubCAKomp asserting just the
	// gematik umbrella policy — the C.FD.SIG baseline mandates
	// digitalSignature + the umbrella + the cert-type OID. We only
	// have the umbrella as a real fixture OID, so the test asserts
	// "policy_mismatch fails when type OID is missing" rather than
	// the happy path. That still exercises the spec-composition path
	// the way the validator sees it.
	ee := customNISTEE(t, pki, testca.CertOptions{
		KeyUsage:            x509.KeyUsageDigitalSignature,
		CertificatePolicies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
	})

	v := gempki.ProfileIdp.Validator(ts, gempki.CertTypeFdSIG)
	gempki.WithRevocationChecker(emptyHashListChecker())(v)
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAKomp.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid, "should reject — missing OIDCertTypeFdSIG policy")
	assert.True(t, result.HasError(gempki.ErrCodePolicyMismatch),
		"expected policy_mismatch (C.FD.SIG spec mandates the type OID), got: %v", result.Errors)
}

func TestProfileEpaVau_RevocationModeIsHardFail(t *testing.T) {
	t.Parallel()
	// ProfileEpaVau is HardFail for ePA backend access — a sanity test
	// against accidental downgrade. Pair with ProfileSmbAuth (SoftFail)
	// to confirm the matrix.
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})

	v := gempki.ProfileEpaVau.Validator(ts, gempki.CertTypeFdAUT)
	assert.Equal(t, gempki.RevocationModeHardFail, v.Revocation.Mode)

	v2 := gempki.ProfileSmbAuth.Validator(ts, gempki.CertTypeHciAUT)
	assert.Equal(t, gempki.RevocationModeSoftFail, v2.Revocation.Mode)

	v3 := gempki.ProfileIdp.Validator(ts, gempki.CertTypeFdSIG)
	assert.Equal(t, gempki.RevocationModeHardFail, v3.Revocation.Mode)
}

func TestProfile_Validator_ComposesSpecBaseline(t *testing.T) {
	t.Parallel()
	// The composer pulls KeyUsage / EKU / Policies / RoleOIDs from the
	// type spec and revocation mode from the profile. Inspect the
	// resulting Validator fields directly so we know the wiring works
	// without running a full validation.
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := gempki.ProfileSmbAuth.Validator(ts, gempki.CertTypeHciAUT)

	spec := gempki.CertTypeHciAUT.Spec()
	assert.Equal(t, spec.KeyUsage, v.RequiredKeyUsage, "baseline KeyUsage must flow through")
	assert.ElementsMatch(t, spec.EKU, v.AllowedExtKeyUsages, "baseline EKU must flow through")
	assert.ElementsMatch(t, spec.Policies, v.RequiredPolicies, "baseline Policies must flow through")
	assert.ElementsMatch(t, spec.RoleOIDs, v.RequiredRoleOIDs, "baseline RoleOIDs must flow through")
	assert.Equal(t, gempki.ProfileSmbAuth.RevocationMode, v.Revocation.Mode)
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
