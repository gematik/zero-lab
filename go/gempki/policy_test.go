package gempki_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certWithPolicies builds a fresh EE cert (under SubCAHBA) asserting the
// given CertificatePolicies. Returns the parsed cert.
func certWithPolicies(t *testing.T, pki *testca.TestPKI, policies ...asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	opts := testca.CertOptions{
		Subject:             pkix.Name{CommonName: "policy-test EE", Country: []string{"DE"}},
		Serial:              big.NewInt(time.Now().UnixNano()),
		NotBefore:           time.Now().Add(-time.Hour),
		NotAfter:            time.Now().Add(24 * time.Hour),
		KeyUsage:            x509.KeyUsageDigitalSignature,
		CertificatePolicies: policies,
	}
	der, err := testca.CreateCertificate(opts, &pki.EEArzt.Key.PublicKey, pki.SubCAHBA.Cert, pki.SubCAHBA.Key)
	require.NoError(t, err)
	cert, err := gempki.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestCheckCertificatePolicies_PassWhenAllPresent(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	cert := certWithPolicies(t, pki, gempki.OIDPolicyGemOrCP, gempki.OIDPolicyHbaCP)

	check := gempki.CheckCertificatePolicies(gempki.OIDPolicyGemOrCP, gempki.OIDPolicyHbaCP)
	require.NoError(t, check(t.Context(), cert))
}

func TestCheckCertificatePolicies_FailWhenAnyMissing(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	cert := certWithPolicies(t, pki, gempki.OIDPolicyGemOrCP)

	check := gempki.CheckCertificatePolicies(gempki.OIDPolicyGemOrCP, gempki.OIDPolicyHbaCP)
	err = check(t.Context(), cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrPolicyMismatch))
	assert.Contains(t, err.Error(), "1.2.276.0.76.4.145") // OIDPolicyHbaCP (the missing one)
}

func TestCheckCertificatePolicies_EmptyRequirementPasses(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	cert := certWithPolicies(t, pki)
	check := gempki.CheckCertificatePolicies()
	require.NoError(t, check(t.Context(), cert))
}

func TestCheckAnyCertificatePolicy_OneMatchPasses(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	cert := certWithPolicies(t, pki, gempki.OIDPolicyGemOrCP)

	check := gempki.CheckAnyCertificatePolicy(gempki.OIDPolicyHbaCP, gempki.OIDPolicyGemOrCP)
	require.NoError(t, check(t.Context(), cert))
}

func TestCheckAnyCertificatePolicy_NoneMatchFails(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	cert := certWithPolicies(t, pki, gempki.OIDPolicyGemTSLSigner)

	check := gempki.CheckAnyCertificatePolicy(gempki.OIDPolicyHbaCP, gempki.OIDPolicyGemOrCP)
	err = check(t.Context(), cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrPolicyMismatch))
}
