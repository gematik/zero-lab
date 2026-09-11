package gempki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// RevocationChecker consults one source of revocation truth for cert, which
// was issued by issuer. [OCSPChecker] is the implementation; the interface
// exists so validator tests can substitute a stub.
//
// The contract separates two kinds of failure that a caller must never
// confuse:
//
//   - (result, nil): the source answered. Status is Good, Revoked or Unknown
//     — Unknown covering "the responder does not know", "no responder URL"
//     and "the answer is too old to use".
//   - (nil, err): the source could not be consulted, or its answer cannot be
//     trusted. err is a [*ValidationError] whose Code says which:
//     [ErrCodeOCSPUnavailable] for a transient failure (unreachable, HTTP
//     error, undecodable bytes) and [ErrCodeOCSPResponderUntrusted] /
//     [ErrCodeOCSPResponseInvalid] for a response that failed authorization
//     or signature verification. Any other error is a programming error
//     (nil issuer, malformed request) and is returned by [Validator.Validate]
//     as its own error.
//
// Check must be safe for concurrent use.
type RevocationChecker interface {
	Check(ctx context.Context, cert, issuer *x509.Certificate) (*RevocationResult, error)
}

// RevocationMode decides how a non-Good revocation outcome affects the
// verdict. Revoked is always an error and an untrusted response is always
// an error; the mode only governs the transient cases.
type RevocationMode int

const (
	// RevocationModeHardFail rejects on anything other than Status=Good. The
	// zero value, so a Validator that forgets to configure revocation fails
	// closed rather than open.
	RevocationModeHardFail RevocationMode = iota

	// RevocationModeSoftFail records Unknown and transient failures as
	// warnings and accepts the certificate. Revoked, and any response that
	// could not be trusted, are still errors.
	RevocationModeSoftFail

	// RevocationModeDisabled skips revocation checking entirely.
	RevocationModeDisabled
)

// RevocationStatus is what a source said about one certificate.
type RevocationStatus string

const (
	// RevocationStatusGood — the source explicitly says the certificate is valid.
	RevocationStatusGood RevocationStatus = "good"

	// RevocationStatusRevoked — the source explicitly says the certificate is revoked.
	RevocationStatusRevoked RevocationStatus = "revoked"

	// RevocationStatusUnknown — the source has no usable information about
	// this certificate.
	RevocationStatusUnknown RevocationStatus = "unknown"
)

// RevocationResult is the revocation outcome for one certificate.
type RevocationResult struct {
	Status    RevocationStatus
	CheckedAt time.Time
	RevokedAt time.Time // zero unless Status == Revoked
	Reason    string    // human-readable

	// OCSP detail, populated when a response decoded successfully — for
	// display and diagnostics.
	ResponderURL  string            // the OCSP endpoint we queried
	ProducedAt    time.Time         // BasicOCSPResponse.tbsResponseData.producedAt
	ThisUpdate    time.Time         // SingleResponse.thisUpdate
	NextUpdate    time.Time         // SingleResponse.nextUpdate (zero if absent)
	Responder     *x509.Certificate // embedded responder cert, nil if responder == issuer
	ResponderName string            // CommonName of the signer (Responder or issuer)
	RawResponse   []byte            // raw DER bytes of the OCSP response, kept for forensic dumps
}

// applyRevocation maps one checker outcome onto the result vocabulary. It
// is the single place the mode is interpreted:
//
//	outcome                          HardFail  SoftFail
//	Good                             —         —
//	Revoked                          error     error
//	Unknown / unavailable            error     warning
//	responder untrusted / invalid    error     error
//
// The last row is the point: a response that failed authorization or
// signature verification is evidence of something wrong, not of a flaky
// responder, and no mode may turn it into a warning.
func applyRevocation(mode RevocationMode, cn string, result *RevocationResult, err error) (*ValidationError, *ValidationWarning) {
	if err != nil {
		var ve *ValidationError
		if !errors.As(err, &ve) {
			// Not a checker verdict; the caller reports it as a failure of
			// its own. Defensive: OCSPChecker never returns anything else.
			return &ValidationError{
				Code:    ErrCodeOCSPUnavailable,
				Subject: cn,
				Message: "revocation check failed",
				Cause:   err,
			}, nil
		}
		if ve.Subject == "" {
			ve.Subject = cn
		}
		switch ve.Code {
		case ErrCodeOCSPResponderUntrusted, ErrCodeOCSPResponseInvalid:
			return ve, nil
		}
		if mode == RevocationModeSoftFail {
			return nil, &ValidationWarning{Code: ve.Code, Subject: cn, Message: ve.Message}
		}
		return ve, nil
	}

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
	}
	if mode == RevocationModeSoftFail {
		return nil, &ValidationWarning{
			Code:    ErrCodeOCSPUnavailable,
			Subject: cn,
			Message: "revocation status unknown: " + result.Reason,
		}
	}
	return &ValidationError{
		Code:    ErrCodeOCSPUnavailable,
		Subject: cn,
		Message: "revocation status unknown: " + result.Reason,
	}, nil
}
