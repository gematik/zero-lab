package gempki

import (
	"context"
	"crypto/x509"
)

// ValidationHooks is an opt-in observation surface for [Validator].Validate.
//
// Each field is an optional callback fired at a fixed point in the
// validation pipeline. Use it for distributed tracing spans, audit logging,
// metrics, structured error capture — anything you don't want hardcoded in
// the validator itself. Hooks must not panic; the validator does not
// recover from them.
//
// All fields are nil-safe — set only the ones you need. A nil
// *ValidationHooks is equivalent to all-nil callbacks.
type ValidationHooks struct {
	// BeforeChainBuild fires once, before the leaf is matched against
	// intermediates and the trust store. err is always nil here.
	BeforeChainBuild func(ctx context.Context, leaf *x509.Certificate)

	// AfterChainBuild fires once after chain construction. chain is the
	// ordered chain on success; nil + err on failure.
	AfterChainBuild func(ctx context.Context, chain []*x509.Certificate, err error)

	// BeforeRevocation fires immediately before the revocation subsystem
	// runs, with the fully-built chain.
	BeforeRevocation func(ctx context.Context, chain []*x509.Certificate)

	// AfterRevocation fires once revocation evaluation finishes. outcome may
	// be partial when err is non-nil.
	AfterRevocation func(ctx context.Context, outcome *RevocationOutcome, err error)

	// OnError fires once per [ValidationError] recorded in the result.
	// Use to push errors into a metrics counter labelled by ErrorCode.
	OnError func(ctx context.Context, err *ValidationError)

	// OnWarning fires once per [ValidationWarning] recorded in the result.
	OnWarning func(ctx context.Context, warn *ValidationWarning)
}

// fireBeforeChainBuild invokes the callback if hooks and the callback are
// both non-nil. Centralising the nil checks keeps the call sites in
// validate.go terse.
func (h *ValidationHooks) fireBeforeChainBuild(ctx context.Context, leaf *x509.Certificate) {
	if h != nil && h.BeforeChainBuild != nil {
		h.BeforeChainBuild(ctx, leaf)
	}
}

func (h *ValidationHooks) fireAfterChainBuild(ctx context.Context, chain []*x509.Certificate, err error) {
	if h != nil && h.AfterChainBuild != nil {
		h.AfterChainBuild(ctx, chain, err)
	}
}

func (h *ValidationHooks) fireBeforeRevocation(ctx context.Context, chain []*x509.Certificate) {
	if h != nil && h.BeforeRevocation != nil {
		h.BeforeRevocation(ctx, chain)
	}
}

func (h *ValidationHooks) fireAfterRevocation(ctx context.Context, outcome *RevocationOutcome, err error) {
	if h != nil && h.AfterRevocation != nil {
		h.AfterRevocation(ctx, outcome, err)
	}
}

func (h *ValidationHooks) fireOnError(ctx context.Context, err *ValidationError) {
	if h != nil && h.OnError != nil && err != nil {
		h.OnError(ctx, err)
	}
}

func (h *ValidationHooks) fireOnWarning(ctx context.Context, warn *ValidationWarning) {
	if h != nil && h.OnWarning != nil && warn != nil {
		h.OnWarning(ctx, warn)
	}
}
