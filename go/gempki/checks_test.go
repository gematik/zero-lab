package gempki_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckKeyUsage_PassWhenAllBitsPresent(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// EEArzt has KeyUsageDigitalSignature (set by eeOpts).
	check := gempki.CheckKeyUsage(x509.KeyUsageDigitalSignature)
	require.NoError(t, check(t.Context(), pki.EEArzt.Cert))
}

func TestCheckKeyUsage_FailWhenRequiredBitMissing(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// EEArzt does NOT have KeyUsageContentCommitment.
	check := gempki.CheckKeyUsage(x509.KeyUsageContentCommitment)
	err = check(t.Context(), pki.EEArzt.Cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrKeyUsageMismatch))
	assert.Contains(t, err.Error(), "contentCommitment")
}

func TestCheckKeyUsage_MultipleBits(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// RCA1 (root) has KeyCertSign | CRLSign.
	check := gempki.CheckKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign)
	require.NoError(t, check(t.Context(), pki.RCA1.Cert))

	// And missing one of two should fail.
	check2 := gempki.CheckKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature)
	require.Error(t, check2(t.Context(), pki.RCA1.Cert))
}

func TestCheckExtKeyUsage_PassWhenAllPresent(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// EEZeta has ExtKeyUsageServerAuth.
	check := gempki.CheckExtKeyUsage(x509.ExtKeyUsageServerAuth)
	require.NoError(t, check(t.Context(), pki.EEZeta.Cert))
}

func TestCheckExtKeyUsage_FailWhenMissing(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// EEZeta doesn't have id-kp-OCSPSigning.
	check := gempki.CheckExtKeyUsage(x509.ExtKeyUsageOCSPSigning)
	err = check(t.Context(), pki.EEZeta.Cert)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrKeyUsageMismatch))
}

func TestCheckHasAnyExtKeyUsage(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)

	// EEZeta has serverAuth; pass when serverAuth is in the allow list.
	check := gempki.CheckHasAnyExtKeyUsage(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)
	require.NoError(t, check(t.Context(), pki.EEZeta.Cert))

	// Fail when none of allowed matches.
	check2 := gempki.CheckHasAnyExtKeyUsage(x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageTimeStamping)
	require.Error(t, check2(t.Context(), pki.EEZeta.Cert))
}

func TestValidatePath_RunsEEChecks(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	chain := buildChainHelper(t, pki.EEArzt.Cert, []*x509.Certificate{pki.SubCAHBA.Cert}, ts)

	// EEArzt only has clientAuth (set by eeOpts default). Demanding serverAuth
	// must trip the EEChecks pipeline.
	result, err := gempki.ValidatePath(t.Context(), chain, gempki.ValidatePathOptions{
		EEChecks: []gempki.CertificateCheck{
			gempki.CheckExtKeyUsage(x509.ExtKeyUsageServerAuth),
		},
	})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.True(t, result.HasError(gempki.ErrCodeKeyUsageMismatch))
}
