package gempki_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
)

func TestValidationError_ErrorsIs_MatchesByCode(t *testing.T) {
	t.Parallel()

	// A concrete instance with subject + cause should still be Is-equal to
	// the sentinel whose only meaningful field is the code.
	concrete := &gempki.ValidationError{
		Code:    gempki.ErrCodeRevoked,
		Subject: "CN=arzt.example",
		Cause:   fmt.Errorf("OCSP returned revoked at 2026-06-04"),
	}
	assert.True(t, errors.Is(concrete, &gempki.ValidationError{Code: gempki.ErrCodeRevoked}),
		"concrete error must match a bare-code target by code")
	assert.False(t, errors.Is(concrete, &gempki.ValidationError{Code: gempki.ErrCodeExpired}),
		"different code must not match")
}

func TestValidationError_ErrorsIs_DoesNotMatchPlainError(t *testing.T) {
	t.Parallel()

	concrete := &gempki.ValidationError{Code: gempki.ErrCodeRevoked, Subject: "x"}
	assert.False(t, errors.Is(concrete, errors.New("revoked")))
}

func TestValidationError_Unwrap(t *testing.T) {
	t.Parallel()

	root := errors.New("network error")
	v := &gempki.ValidationError{
		Code:    gempki.ErrCodeOCSPUnavailable,
		Subject: "CN=ocsp",
		Cause:   root,
	}
	assert.True(t, errors.Is(v, root), "Unwrap must expose Cause to errors.Is")
}

func TestValidationError_ErrorString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  *gempki.ValidationError
		want []string // substrings expected in Error()
	}{
		{
			name: "code_only",
			err:  &gempki.ValidationError{Code: gempki.ErrCodeRevoked, Message: "msg"},
			want: []string{"gempki[revoked]", "msg"},
		},
		{
			name: "with_subject",
			err: &gempki.ValidationError{
				Code: gempki.ErrCodeExpired, Subject: "CN=a", Message: "msg",
			},
			want: []string{"gempki[expired]", "msg", "CN=a"},
		},
		{
			name: "with_cause",
			err: &gempki.ValidationError{
				Code: gempki.ErrCodeChainIncomplete, Message: "msg",
				Cause: errors.New("aki mismatch"),
			},
			want: []string{"gempki[chain_incomplete]", "msg", "aki mismatch"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := tc.err.Error()
			for _, sub := range tc.want {
				assert.Contains(t, s, sub)
			}
		})
	}
}

func TestErrChainIncomplete_IsWrappedByBuildChain(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("outer: %w", gempki.ErrChainIncomplete)
	assert.True(t, errors.Is(wrapped, gempki.ErrChainIncomplete))
	assert.True(t, errors.Is(wrapped, &gempki.ValidationError{Code: gempki.ErrCodeChainIncomplete}))
}
