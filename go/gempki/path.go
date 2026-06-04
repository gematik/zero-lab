package gempki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ValidatePathOptions configures [ValidatePath].
type ValidatePathOptions struct {
	// TimeFunc returns "now" for validity checks. Defaults to [time.Now] when
	// nil. Override for historical validation (e.g. signature time).
	TimeFunc func() time.Time

	// EEChecks, SubCAChecks, RootChecks run after RFC 5280 checks pass.
	// Each is invoked with the relevant cert; any non-nil return becomes a
	// [ValidationError] in the result.
	EEChecks    []CertificateCheck
	SubCAChecks []CertificateCheck
	RootChecks  []CertificateCheck
}

// ValidatePath validates a chain built by [BuildChain] against RFC 5280 §6
// requirements and the caller's per-tier checks.
//
// Checks applied to every cert: notBefore ≤ now ≤ notAfter. Checks applied
// to every non-EE cert: IsCA must be set, KeyUsage must include KeyCertSign,
// and the PathLenConstraint (if asserted) is respected by the number of
// intermediates beneath it. Each adjacent pair is verified via
// [VerifyCertificateSignature] — RSA at any link surfaces
// [ErrRSANotSupported] without special handling here.
//
// chain must be ordered [EE, SubCA…, Root]. ValidatePath returns a
// [ValidationResult] with Valid=false and one or more Errors when checks fail;
// the second return value is non-nil only for argument-shape problems (nil
// chain, nil ctx).
func ValidatePath(ctx context.Context, chain []*x509.Certificate, opts ValidatePathOptions) (*ValidationResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gempki: ValidatePath requires a non-nil context")
	}
	if len(chain) < 2 {
		return nil, fmt.Errorf("gempki: ValidatePath requires a chain of at least [EE, Root] (got %d)", len(chain))
	}

	now := time.Now()
	if opts.TimeFunc != nil {
		now = opts.TimeFunc()
	}

	result := &ValidationResult{
		Valid:       true,
		Chain:       chain,
		Positions:   make([]ChainPosition, len(chain)),
		CertResults: make([]CertResult, len(chain)),
	}
	for i := range chain {
		result.Positions[i] = positionOf(i, len(chain))
		result.CertResults[i] = CertResult{
			Subject:  chain[i].Subject.CommonName,
			Position: result.Positions[i],
		}
	}

	for i, cert := range chain {
		pos := result.Positions[i]

		if err := checkValidity(cert, now); err != nil {
			result.add(err)
		}
		if pos != PositionEE {
			if err := checkCAConstraints(cert, intermediatesBelow(i)); err != nil {
				result.add(err)
			}
		}
		if i+1 < len(chain) {
			if err := VerifyCertificateSignature(cert, chain[i+1]); err != nil {
				result.add(&ValidationError{
					Code:    ErrCodeSignatureInvalid,
					Subject: cert.Subject.CommonName,
					Message: "chain signature verification failed",
					Cause:   err,
				})
			}
		}

		var checks []CertificateCheck
		switch pos {
		case PositionEE:
			checks = opts.EEChecks
		case PositionSubCA:
			checks = opts.SubCAChecks
		case PositionRoot:
			checks = opts.RootChecks
		}
		for _, c := range checks {
			if err := c(ctx, cert); err != nil {
				result.add(toValidationError(err, cert))
			}
		}
	}

	return result, nil
}

func positionOf(i, length int) ChainPosition {
	switch i {
	case 0:
		return PositionEE
	case length - 1:
		return PositionRoot
	default:
		return PositionSubCA
	}
}

// intermediatesBelow returns the count of intermediate CAs beneath the cert
// at chain index rootIdx — the EE at index 0 doesn't count, so the answer is
// max(0, rootIdx-1). Used to check PathLenConstraint.
func intermediatesBelow(rootIdx int) int {
	below := rootIdx - 1
	if below < 0 {
		return 0
	}
	return below
}

func checkValidity(cert *x509.Certificate, now time.Time) *ValidationError {
	if now.Before(cert.NotBefore) {
		return &ValidationError{
			Code:    ErrCodeNotYetValid,
			Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("notBefore=%s, now=%s", cert.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339)),
		}
	}
	if now.After(cert.NotAfter) {
		return &ValidationError{
			Code:    ErrCodeExpired,
			Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("notAfter=%s, now=%s", cert.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339)),
		}
	}
	return nil
}

func checkCAConstraints(cert *x509.Certificate, intermediatesBelow int) *ValidationError {
	if !cert.IsCA {
		return &ValidationError{
			Code:    ErrCodeChainIncomplete,
			Subject: cert.Subject.CommonName,
			Message: "non-root, non-EE certificate is not marked CA",
		}
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &ValidationError{
			Code:    ErrCodeKeyUsageMismatch,
			Subject: cert.Subject.CommonName,
			Message: "CA certificate missing KeyUsageCertSign",
		}
	}
	if cert.MaxPathLenZero || cert.MaxPathLen > 0 {
		// MaxPathLen == 0 with MaxPathLenZero true means "no intermediates
		// allowed below me." MaxPathLen > 0 means "at most N intermediates
		// allowed below me."
		allowed := cert.MaxPathLen
		if cert.MaxPathLenZero {
			allowed = 0
		}
		if intermediatesBelow > allowed {
			return &ValidationError{
				Code:    ErrCodeChainIncomplete,
				Subject: cert.Subject.CommonName,
				Message: fmt.Sprintf("PathLenConstraint exceeded: max=%d, below=%d", allowed, intermediatesBelow),
			}
		}
	}
	return nil
}

// add appends an error to the result and flips Valid to false.
func (r *ValidationResult) add(err *ValidationError) {
	if err == nil {
		return
	}
	r.Errors = append(r.Errors, err)
	r.Valid = false
}

// toValidationError converts an arbitrary check error into a *ValidationError.
// If err is or wraps a *ValidationError, that wrapped value is returned with
// Subject filled in when missing. Otherwise the error is wrapped under
// ErrCodeKeyUsageMismatch — built-in checks are expected to return
// *ValidationError already, so this is a defensive fallback for callers'
// custom checks.
func toValidationError(err error, cert *x509.Certificate) *ValidationError {
	var ve *ValidationError
	if errors.As(err, &ve) {
		if ve.Subject == "" {
			ve.Subject = cert.Subject.CommonName
		}
		return ve
	}
	return &ValidationError{
		Code:    ErrCodeKeyUsageMismatch,
		Subject: cert.Subject.CommonName,
		Message: "custom check failed",
		Cause:   err,
	}
}
