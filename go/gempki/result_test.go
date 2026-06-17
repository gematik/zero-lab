package gempki_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
)

func TestValidationResult_HasError(t *testing.T) {
	t.Parallel()

	r := &gempki.ValidationResult{
		Errors: []*gempki.ValidationError{
			{Code: gempki.ErrCodeExpired, Subject: "CN=a"},
			{Code: gempki.ErrCodeChainIncomplete, Subject: "CN=b"},
		},
	}
	assert.True(t, r.HasError(gempki.ErrCodeExpired))
	assert.True(t, r.HasError(gempki.ErrCodeChainIncomplete))
	assert.False(t, r.HasError(gempki.ErrCodeRevoked))
}

func TestValidationResult_HasError_NilSafe(t *testing.T) {
	t.Parallel()

	var r *gempki.ValidationResult
	assert.False(t, r.HasError(gempki.ErrCodeExpired))

	r2 := &gempki.ValidationResult{}
	assert.False(t, r2.HasError(gempki.ErrCodeExpired))
}
