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

// validateWith runs the Brainpool fixture chain through a validator with
// the given revocation mode and checker.
func validateWith(t *testing.T, mode gempki.RevocationMode, checker gempki.RevocationChecker) *gempki.ValidationResult {
	t.Helper()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	v := &gempki.Validator{TrustStore: ts, RevocationMode: mode, Revocation: checker}
	result, err := v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.NoError(t, err)
	return result
}

func codes(errs []*gempki.ValidationError) []gempki.ErrorCode {
	var out []gempki.ErrorCode
	for _, e := range errs {
		out = append(out, e.Code)
	}
	return out
}

func warningCodes(ws []*gempki.ValidationWarning) []gempki.ErrorCode {
	var out []gempki.ErrorCode
	for _, w := range ws {
		out = append(out, w.Code)
	}
	return out
}

func TestRevocation_DisabledSkipsChecker(t *testing.T) {
	t.Parallel()
	// The checker would reject; Disabled must never call it.
	result := validateWith(t, gempki.RevocationModeDisabled, revokedChecker("must not be consulted"))
	assert.True(t, result.Valid, "errors: %v", result.Errors)
	assert.Empty(t, result.Warnings)
	assert.Nil(t, result.CertResults[0].Revocation)
}

func TestRevocation_GoodIsSilent(t *testing.T) {
	t.Parallel()
	for _, mode := range []gempki.RevocationMode{gempki.RevocationModeHardFail, gempki.RevocationModeSoftFail} {
		result := validateWith(t, mode, goodChecker())
		assert.True(t, result.Valid, "mode %d: %v", mode, result.Errors)
		assert.Empty(t, result.Warnings)
		require.NotNil(t, result.CertResults[0].Revocation)
		assert.Equal(t, gempki.RevocationStatusGood, result.CertResults[0].Revocation.Status)
	}
}

func TestRevocation_RevokedFailsUnderEveryMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []gempki.RevocationMode{gempki.RevocationModeHardFail, gempki.RevocationModeSoftFail} {
		result := validateWith(t, mode, revokedChecker("keyCompromise"))
		assert.False(t, result.Valid, "mode %d must reject a revoked certificate", mode)
		assert.Equal(t, []gempki.ErrorCode{gempki.ErrCodeRevoked}, codes(result.Errors))
	}
}

// TestRevocation_ModeTable pins the one table that decides how each checker
// outcome affects the verdict. The two bottom rows are the point: a response
// that could not be trusted is an error no matter how lenient the mode.
func TestRevocation_ModeTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		checker      gempki.RevocationChecker
		hardErrors   []gempki.ErrorCode
		softErrors   []gempki.ErrorCode
		softWarnings []gempki.ErrorCode
	}{
		{
			name:         "unknown",
			checker:      unknownChecker(),
			hardErrors:   []gempki.ErrorCode{gempki.ErrCodeOCSPUnavailable},
			softWarnings: []gempki.ErrorCode{gempki.ErrCodeOCSPUnavailable},
		},
		{
			name:         "unavailable",
			checker:      failingChecker(gempki.ErrCodeOCSPUnavailable),
			hardErrors:   []gempki.ErrorCode{gempki.ErrCodeOCSPUnavailable},
			softWarnings: []gempki.ErrorCode{gempki.ErrCodeOCSPUnavailable},
		},
		{
			name:       "responder untrusted",
			checker:    failingChecker(gempki.ErrCodeOCSPResponderUntrusted),
			hardErrors: []gempki.ErrorCode{gempki.ErrCodeOCSPResponderUntrusted},
			softErrors: []gempki.ErrorCode{gempki.ErrCodeOCSPResponderUntrusted},
		},
		{
			name:       "response invalid",
			checker:    failingChecker(gempki.ErrCodeOCSPResponseInvalid),
			hardErrors: []gempki.ErrorCode{gempki.ErrCodeOCSPResponseInvalid},
			softErrors: []gempki.ErrorCode{gempki.ErrCodeOCSPResponseInvalid},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			hard := validateWith(t, gempki.RevocationModeHardFail, c.checker)
			assert.Equal(t, c.hardErrors, codes(hard.Errors), "HardFail errors")
			assert.Empty(t, hard.Warnings, "HardFail never warns")
			assert.False(t, hard.Valid)

			soft := validateWith(t, gempki.RevocationModeSoftFail, c.checker)
			assert.Equal(t, c.softErrors, codes(soft.Errors), "SoftFail errors")
			assert.Equal(t, c.softWarnings, warningCodes(soft.Warnings), "SoftFail warnings")
			assert.Equal(t, len(c.softErrors) == 0, soft.Valid)
		})
	}
}

func TestRevocation_NoCheckerFailsClosed(t *testing.T) {
	t.Parallel()
	for _, mode := range []gempki.RevocationMode{gempki.RevocationModeHardFail, gempki.RevocationModeSoftFail} {
		result := validateWith(t, mode, nil)
		assert.False(t, result.Valid, "mode %d with no checker must reject", mode)
		assert.Equal(t, []gempki.ErrorCode{gempki.ErrCodeOCSPUnavailable}, codes(result.Errors))
	}
}

func TestRevocation_CheckerContractViolationIsCallersError(t *testing.T) {
	t.Parallel()
	// A plain error is outside the checker contract — a bug, not a verdict —
	// and surfaces as Validate's own error rather than a result entry.
	pki, err := testca.New()
	require.NoError(t, err)
	ts, _ := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	v := &gempki.Validator{TrustStore: ts, Revocation: stubChecker{err: errors.New("nil issuer")}}
	_, err = v.Validate(t.Context(), []*x509.Certificate{pki.EEArzt.Cert, pki.SubCAHBA.Cert})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil issuer")
}
