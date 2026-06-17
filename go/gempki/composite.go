package gempki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// FallbackOrder controls how [CompositeChecker] combines results from
// multiple sources.
type FallbackOrder int

const (
	// FallbackPriority returns the first checker's result that is
	// Good or Revoked. Checkers that error or return Unknown are skipped.
	// If every checker yields Unknown/error, the composite returns Unknown
	// with all reasons concatenated.
	FallbackPriority FallbackOrder = iota

	// FallbackAllAgree requires every checker to produce a definitive result
	// (Good or Revoked) and to agree. Any disagreement, error, or Unknown
	// yields Status=Unknown.
	FallbackAllAgree
)

// CompositeChecker wraps multiple [RevocationChecker]s under a single
// [FallbackOrder] policy.
//
// FallbackPriority is the "OCSP primary, hash list fallback" pattern: try
// OCSP first, only fall through when it's unreachable. FallbackAllAgree is
// the conservative "both sources must say good" pattern: useful when neither
// alone is trusted, e.g. when an OCSP endpoint may be stale and the hash
// list may be incomplete.
type CompositeChecker struct {
	Checkers []RevocationChecker
	Order    FallbackOrder
}

// Check implements [RevocationChecker]. See [FallbackOrder] for the
// per-mode semantics.
func (c CompositeChecker) Check(ctx context.Context, cert, issuer *x509.Certificate) (*RevocationResult, error) {
	if len(c.Checkers) == 0 {
		return nil, fmt.Errorf("gempki: CompositeChecker has no Checkers")
	}
	switch c.Order {
	case FallbackPriority:
		return c.checkPriority(ctx, cert, issuer)
	case FallbackAllAgree:
		return c.checkAllAgree(ctx, cert, issuer)
	}
	return nil, fmt.Errorf("gempki: unknown FallbackOrder %d", c.Order)
}

func (c CompositeChecker) checkPriority(ctx context.Context, cert, issuer *x509.Certificate) (*RevocationResult, error) {
	var (
		errs    []error
		reasons []string
		lastUnk *RevocationResult
	)
	for _, ch := range c.Checkers {
		r, err := ch.Check(ctx, cert, issuer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if r == nil {
			continue
		}
		if r.Status == RevocationStatusGood || r.Status == RevocationStatusRevoked {
			return r, nil
		}
		lastUnk = r
		if r.Reason != "" {
			reasons = append(reasons, r.Reason)
		}
	}
	if lastUnk != nil {
		// Preserve the last Unknown result but enrich its reason.
		lastUnk.Reason = joinNonEmpty("; ", append(reasons, errStrings(errs)...))
		return lastUnk, nil
	}
	// No checker produced any result — return the joined errors so the
	// caller (EvaluateChain) treats this as a checker failure.
	return nil, errors.Join(errs...)
}

func (c CompositeChecker) checkAllAgree(ctx context.Context, cert, issuer *x509.Certificate) (*RevocationResult, error) {
	var (
		consensus *RevocationResult
		errs      []error
	)
	for _, ch := range c.Checkers {
		r, err := ch.Check(ctx, cert, issuer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if r == nil || r.Status == RevocationStatusUnknown {
			return &RevocationResult{
				Status:    RevocationStatusUnknown,
				CheckedAt: time.Now(),
				Reason:    "AllAgree: at least one checker returned Unknown",
			}, nil
		}
		if consensus == nil {
			consensus = r
			continue
		}
		if consensus.Status != r.Status {
			return &RevocationResult{
				Status:    RevocationStatusUnknown,
				CheckedAt: time.Now(),
				Reason: fmt.Sprintf("AllAgree: disagreement (%s vs %s)",
					consensus.Status, r.Status),
			}, nil
		}
	}
	if consensus == nil {
		// Every checker errored.
		return nil, errors.Join(errs...)
	}
	return consensus, nil
}

func errStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}

func joinNonEmpty(sep string, parts []string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}
