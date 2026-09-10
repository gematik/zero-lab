package gempki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customEE builds an EE under SubCAHBA with custom options (admission,
// policies, KU, EKU) for end-to-end testing.
func customEE(t *testing.T, pki *testca.TestPKI, opts testca.CertOptions) *x509.Certificate {
	t.Helper()
	if opts.Subject.CommonName == "" {
		opts.Subject = pkix.Name{CommonName: "custom EE", Country: []string{"DE"}}
	}
	opts.Serial = big.NewInt(time.Now().UnixNano())
	opts.NotBefore = time.Now().Add(-time.Hour)
	opts.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := testca.CreateCertificate(opts, &pki.EEArzt.Key.PublicKey, pki.SubCAHBA.Cert, pki.SubCAHBA.Key)
	require.NoError(t, err)
	cert, err := gempki.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestValidator_BrainpoolHappyPath(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := &gempki.Validator{TrustStore: ts, Revocation: goodChecker()}
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_RequiresTrustStore(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	v := &gempki.Validator{Revocation: goodChecker()}
	_, err = v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert})
	require.Error(t, err)
}

func TestValidator_RejectsEmptyChain(t *testing.T) {
	t.Parallel()
	ts, _ := gempki.NewTrustStore(nil)
	v := &gempki.Validator{TrustStore: ts, Revocation: goodChecker()}
	_, err := v.Validate(t.Context(), nil)
	require.Error(t, err)
}

func TestValidator_ChainBuildFailureBecomesValidationError(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	// Trust store has RCA7 (NIST), but the EE chain is Brainpool — no path.
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	v := &gempki.Validator{TrustStore: ts, Revocation: goodChecker()}

	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err, "shape-OK input should never error out")
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeChainIncomplete))
}

func TestValidator_ZeroValueFailsClosed(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	// HardFail is the zero mode and no checker is set: the certificate must
	// be rejected, not waved through because nobody asked.
	v := &gempki.Validator{TrustStore: ts}
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeOCSPUnavailable))
}

func TestValidator_RequiredRoleOID_Pass(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := &gempki.Validator{
		TrustStore:       ts,
		Revocation:       goodChecker(),
		RequiredRoleOIDs: []asn1.ObjectIdentifier{gempki.OIDProfArzt}, // EEArzt has this OID via testca
	}
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_RequiredRoleOID_Fail(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := &gempki.Validator{
		TrustStore:       ts,
		Revocation:       goodChecker(),
		RequiredRoleOIDs: []asn1.ObjectIdentifier{gempki.OIDProfZahnarzt}, // EEArzt has Arzt, not Zahnarzt
	}
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeRoleOIDMissing))
}

func TestValidator_RequiredPolicies_Pass(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	ee := customEE(t, pki, testca.CertOptions{
		KeyUsage:            x509.KeyUsageDigitalSignature,
		CertificatePolicies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
	})
	v := &gempki.Validator{
		TrustStore:       ts,
		Revocation:       goodChecker(),
		RequiredPolicies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
	}
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_RequiredPolicies_Fail(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	ee := customEE(t, pki, testca.CertOptions{KeyUsage: x509.KeyUsageDigitalSignature}) // no policies
	v := &gempki.Validator{
		TrustStore:       ts,
		Revocation:       goodChecker(),
		RequiredPolicies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
	}
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodePolicyMismatch))
}

func TestValidator_RevocationFolding(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := &gempki.Validator{TrustStore: ts, Revocation: revokedChecker("test")}
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EERevoked.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeRevoked))
	// The per-cert revocation result must be stitched onto CertResults.
	require.Len(t, result.CertResults, 3)
	require.NotNil(t, result.CertResults[0].Revocation)
	assert.Equal(t, gempki.RevocationStatusRevoked, result.CertResults[0].Revocation.Status)
}

func TestValidator_ValidatePEM_RoundTrip(t *testing.T) {
	t.Parallel()
	pemAll := []byte(fixtureBrainpoolSMCBEEPEM + "\n" +
		fixtureBrainpoolSMCBCA51PEM + "\n" +
		fixtureBrainpoolRCA5PEM)
	rca5, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore(rca5)

	// The fixture certs were minted with notBefore in 2021/2023 and notAfter
	// in 2028/2031 — well within validity for today's clock.
	v := &gempki.Validator{TrustStore: ts, Revocation: goodChecker()}
	result, err := v.ValidatePEM(t.Context(), pemAll)
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}
