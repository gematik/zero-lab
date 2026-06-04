package gempki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// RevocationChecker is one source of revocation truth. Implementations live
// elsewhere: [OCSPChecker] (online), [HashListChecker] (offline list),
// [CompositeChecker] (fallback/agreement across sources).
//
// Check must be safe for concurrent use. The issuer is required so the
// checker can compute the OCSP request's IssuerNameHash / IssuerKeyHash or
// the hash-list key.
type RevocationChecker interface {
	Check(ctx context.Context, cert, issuer *x509.Certificate) (*RevocationResult, error)
}

// RevocationMode controls how [EvaluateChain] reacts to non-Good outcomes.
type RevocationMode int

const (
	// RevocationModeHardFail rejects on anything other than Status=Good.
	// Unknown and check-errored cases become validation errors.
	// This is the conservative default for QES / institutional validation.
	RevocationModeHardFail RevocationMode = iota

	// RevocationModeSoftFail records Unknown / Errored as warnings and
	// accepts the cert. Revoked is still a hard failure.
	RevocationModeSoftFail

	// RevocationModeBestEffort runs checkers but never blocks on their
	// outcome — except Revoked, which is always a hard failure.
	RevocationModeBestEffort

	// RevocationModeDisabled skips revocation checking entirely.
	RevocationModeDisabled
)

// RevocationDecision is the per-cert verdict emitted by [ApplyMode].
type RevocationDecision int

const (
	// RevocationDecisionAccept — caller may treat the cert as not revoked.
	RevocationDecisionAccept RevocationDecision = iota

	// RevocationDecisionReject — caller MUST reject the cert.
	RevocationDecisionReject
)

// RevocationPolicy bundles everything [EvaluateChain] needs.
//
// Checkers run in the order given. A non-nil Cache is consulted before any
// checker runs and updated with checker results (with TTL derived from the
// result's NextUpdate when available, else CacheDefaultTTL). CheckSubCAs=true
// runs revocation against every cert in the chain except the trust anchor;
// false (default) only checks the end-entity.
type RevocationPolicy struct {
	Mode            RevocationMode
	Checkers        []RevocationChecker
	Cache           RevocationCache
	CheckSubCAs     bool
	CacheDefaultTTL time.Duration
}

// RevocationOutcome is what [EvaluateChain] returns.
//
// PerCert is parallel to the input chain — PerCert[i] is the verdict for
// chain[i] (or nil if that cert was skipped, e.g. the trust anchor or a SubCA
// when CheckSubCAs=false). Errors / Warnings already reflect Mode; callers
// fold them directly into the surrounding [ValidationResult].
type RevocationOutcome struct {
	PerCert  []*RevocationResult
	Errors   []*ValidationError
	Warnings []*ValidationWarning
}

// EvaluateChain runs the revocation policy against chain. chain is ordered
// [EE, SubCA…, Root] (as produced by [BuildChain]).
//
// Behaviour:
//   - Mode == Disabled: returns an empty outcome immediately.
//   - The trust anchor (last element) is never checked — TI roots have no
//     issuer to query.
//   - SubCAs are checked iff policy.CheckSubCAs.
//   - The cache is keyed by issuer-DN + serial. Hits skip the checker call.
//   - Checkers run in policy.Checkers order; the first one to return a
//     non-error result terminates the loop. To combine sources, wrap them in
//     a [CompositeChecker] and pass that as the single checker.
//
// EvaluateChain never returns ctx.Err() as the outer error — context
// cancellation is recorded as a ValidationError under the affected cert.
func EvaluateChain(ctx context.Context, chain []*x509.Certificate, policy RevocationPolicy) (*RevocationOutcome, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gempki: EvaluateChain requires a non-nil context")
	}
	if len(chain) < 2 {
		return nil, fmt.Errorf("gempki: EvaluateChain requires a chain of at least [EE, Root]")
	}
	out := &RevocationOutcome{
		PerCert: make([]*RevocationResult, len(chain)),
	}
	if policy.Mode == RevocationModeDisabled {
		return out, nil
	}
	if len(policy.Checkers) == 0 {
		return nil, fmt.Errorf("gempki: EvaluateChain has no Checkers and Mode is not Disabled")
	}

	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1]
		pos := positionOf(i, len(chain))
		if pos != PositionEE && !policy.CheckSubCAs {
			continue
		}
		result, ve, vw := evaluateOne(ctx, cert, issuer, policy)
		out.PerCert[i] = result
		if ve != nil {
			out.Errors = append(out.Errors, ve)
		}
		if vw != nil {
			out.Warnings = append(out.Warnings, vw)
		}
	}
	return out, nil
}

// evaluateOne handles cache, checker dispatch, and Mode mapping for a single
// (cert, issuer) pair.
func evaluateOne(ctx context.Context, cert, issuer *x509.Certificate, policy RevocationPolicy) (*RevocationResult, *ValidationError, *ValidationWarning) {
	key := RevocationCacheKey(cert)
	if policy.Cache != nil {
		if cached, hit, err := policy.Cache.Get(ctx, key); err == nil && hit && cached != nil {
			ve, vw := applyMode(policy.Mode, cached, cert.Subject.CommonName)
			return cached, ve, vw
		}
	}

	var (
		result  *RevocationResult
		lastErr error
	)
	for _, c := range policy.Checkers {
		result, lastErr = c.Check(ctx, cert, issuer)
		if lastErr == nil && result != nil {
			break
		}
	}

	if result == nil {
		// No checker produced a result; treat as Unknown so Mode rules apply.
		errMsg := "no checker produced a result"
		if lastErr != nil {
			errMsg = lastErr.Error()
		}
		result = &RevocationResult{
			Status:    RevocationStatusUnknown,
			CheckedAt: time.Now(),
			Reason:    errMsg,
		}
	}

	if policy.Cache != nil && result.Status != RevocationStatusUnknown {
		ttl := policy.CacheDefaultTTL
		if ttl <= 0 {
			ttl = time.Hour
		}
		_ = policy.Cache.Put(ctx, key, result, ttl)
	}

	ve, vw := applyMode(policy.Mode, result, cert.Subject.CommonName)
	return result, ve, vw
}

// applyMode maps (Mode, Status) to a ValidationError / ValidationWarning.
// Revoked is always an error regardless of Mode; Good is always silent; the
// non-trivial cases are Unknown under Hard/Soft/BestEffort.
func applyMode(mode RevocationMode, result *RevocationResult, cn string) (*ValidationError, *ValidationWarning) {
	switch result.Status {
	case RevocationStatusGood:
		return nil, nil
	case RevocationStatusRevoked:
		return &ValidationError{
			Code:    ErrCodeRevoked,
			Subject: cn,
			Message: fmt.Sprintf("certificate revoked at %s: %s",
				result.RevokedAt.Format(time.RFC3339), result.Reason),
		}, nil
	case RevocationStatusUnknown:
		switch mode {
		case RevocationModeHardFail:
			return &ValidationError{
				Code:    ErrCodeOCSPUnavailable,
				Subject: cn,
				Message: "revocation status unknown (Mode=HardFail): " + result.Reason,
			}, nil
		case RevocationModeSoftFail, RevocationModeBestEffort:
			return nil, &ValidationWarning{
				Code:    ErrCodeOCSPUnavailable,
				Subject: cn,
				Message: "revocation status unknown: " + result.Reason,
			}
		case RevocationModeDisabled:
			return nil, nil
		}
	}
	return nil, nil
}

// RevocationCacheKey returns the stable cache key for a certificate.
// SHA-256(issuer DN || serial) is short, collision-free in practice, and
// independent of OCSP HashAlgorithm choice.
func RevocationCacheKey(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawIssuer)
	h.Write(cert.SerialNumber.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

// ApplyMode is the exported version of [applyMode] for callers (the Phase 6
// Validator, mainly) that want to interpret a [RevocationResult] outside
// EvaluateChain.
func ApplyMode(mode RevocationMode, result *RevocationResult, certCN string) (*ValidationError, *ValidationWarning) {
	if result == nil {
		return nil, nil
	}
	return applyMode(mode, result, certCN)
}
