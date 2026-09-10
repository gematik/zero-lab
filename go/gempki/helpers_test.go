package gempki_test

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
)

// stubChecker answers every revocation query the same way. It stands in for
// OCSPChecker in validator tests so they exercise mode semantics without
// standing up a responder.
type stubChecker struct {
	result *gempki.RevocationResult
	err    error
}

func (s stubChecker) Check(_ context.Context, _, _ *x509.Certificate) (*gempki.RevocationResult, error) {
	return s.result, s.err
}

func goodChecker() gempki.RevocationChecker {
	return stubChecker{result: &gempki.RevocationResult{Status: gempki.RevocationStatusGood, CheckedAt: time.Now()}}
}

func revokedChecker(reason string) gempki.RevocationChecker {
	return stubChecker{result: &gempki.RevocationResult{
		Status:    gempki.RevocationStatusRevoked,
		CheckedAt: time.Now(),
		RevokedAt: time.Now().Add(-time.Hour),
		Reason:    reason,
	}}
}

func unknownChecker() gempki.RevocationChecker {
	return stubChecker{result: &gempki.RevocationResult{
		Status:    gempki.RevocationStatusUnknown,
		CheckedAt: time.Now(),
		Reason:    "stub: no information",
	}}
}

func failingChecker(code gempki.ErrorCode) gempki.RevocationChecker {
	return stubChecker{err: &gempki.ValidationError{Code: code, Message: "stub: " + string(code)}}
}
