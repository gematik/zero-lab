package gempki_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: minimal HashListChecker that reports Good for everything (an
// empty list) so the Validator's revocation step is satisfied without
// network in unit tests.
func emptyHashListChecker() gempki.RevocationChecker { return gempki.NewHashListChecker() }

// helper: build EE under SubCAHBA with custom options (admission, policies,
// KU, EKU) for end-to-end testing.
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

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
	)
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_RequiresTrustStore(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	v := gempki.NewValidator(gempki.WithRevocationChecker(emptyHashListChecker()))
	_, err = v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert})
	require.Error(t, err)
}

func TestValidator_RejectsEmptyChain(t *testing.T) {
	t.Parallel()
	ts, _ := gempki.NewTrustStore(nil)
	v := gempki.NewValidator(gempki.WithTrustStore(ts), gempki.WithRevocationChecker(emptyHashListChecker()))
	_, err := v.Validate(t.Context(), nil)
	require.Error(t, err)
}

func TestValidator_ChainBuildFailureBecomesValidationError(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	// Trust store has RCA7 (NIST), but EE chain is brainpool — no path.
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	v := gempki.NewValidator(gempki.WithTrustStore(ts), gempki.WithRevocationChecker(emptyHashListChecker()))

	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err, "shape-OK input should never error out")
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeChainIncomplete))
}

func TestValidator_RequiredRoleOID_Pass(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
		gempki.WithRequiredRoleOIDs(gempki.OIDProfArzt), // EEArzt has this OID via testca
	)
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_RequiredRoleOID_Fail(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
		gempki.WithRequiredRoleOIDs(gempki.OIDProfZahnarzt), // EEArzt has Arzt, not Zahnarzt
	)
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
	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
		gempki.WithRequiredPolicies(gempki.OIDPolicyGemOrCP),
	)
	result, err := v.Validate(t.Context(), []*x509.Certificate{ee, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_RequiredPolicies_Fail(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	ee := customEE(t, pki, testca.CertOptions{
		KeyUsage: x509.KeyUsageDigitalSignature,
		// no policies asserted
	})
	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
		gempki.WithRequiredPolicies(gempki.OIDPolicyGemOrCP),
	)
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

	hashlist := gempki.NewHashListChecker()
	hashlist.Add(pki.EERevoked.Cert, gempki.HashListEntry{
		RevokedAt: time.Now().Add(-time.Hour),
		Reason:    "test",
	})
	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(hashlist),
	)
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EERevoked.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeRevoked))
	// Per-cert revocation result must be stitched onto CertResults.
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
	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
	)
	result, err := v.ValidatePEM(t.Context(), pemAll)
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_ValidateDER_RoundTrip(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
	)
	result, err := v.ValidateDER(t.Context(), [][]byte{pki.EEArzt.DER, pki.SubCAHBA.DER})
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestValidator_TrustStoreHolderSwap(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	tsA, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert}) // not the right root
	tsB, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert}) // the right root
	holder := gempki.NewTrustStoreHolder(tsA)

	v := gempki.NewValidator(
		gempki.WithTrustStoreHolder(holder),
		gempki.WithRevocationChecker(emptyHashListChecker()),
	)

	// First call: tsA installed → chain incomplete.
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)

	// Hot swap to tsB.
	require.NoError(t, holder.Set(tsB))

	// Second call: same Validator instance, but the Holder now hands out tsB.
	result, err = v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid, "errors: %v", result.Errors)
}

func TestValidator_HooksFireInOrder(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	var order []string
	rec := func(name string) {
		order = append(order, name)
	}
	hooks := &gempki.ValidationHooks{
		BeforeChainBuild: func(_ context.Context, _ *x509.Certificate) { rec("BeforeChainBuild") },
		AfterChainBuild:  func(_ context.Context, _ []*x509.Certificate, _ error) { rec("AfterChainBuild") },
		BeforeRevocation: func(_ context.Context, _ []*x509.Certificate) { rec("BeforeRevocation") },
		AfterRevocation:  func(_ context.Context, _ *gempki.RevocationOutcome, _ error) { rec("AfterRevocation") },
	}

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
		gempki.WithHooks(hooks),
	)
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t,
		[]string{"BeforeChainBuild", "AfterChainBuild", "BeforeRevocation", "AfterRevocation"},
		order)
}

func TestValidator_OnErrorHookCountsErrors(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})

	var errorCount atomic.Int32
	hooks := &gempki.ValidationHooks{
		OnError: func(_ context.Context, _ *gempki.ValidationError) {
			errorCount.Add(1)
		},
	}
	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationChecker(emptyHashListChecker()),
		gempki.WithRequiredRoleOIDs(gempki.OIDProfZahnarzt), // EEArzt doesn't satisfy this
		gempki.WithHooks(hooks),
	)
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Positive(t, errorCount.Load())
}
