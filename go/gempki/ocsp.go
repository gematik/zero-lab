package gempki

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPNoncePolicy is reserved for Phase 4 nonce enforcement.
type OCSPNoncePolicy int

const (
	// OCSPNoncePreferred sends a nonce but accepts responses without one.
	OCSPNoncePreferred OCSPNoncePolicy = iota

	// OCSPNonceRequired rejects responses that don't echo our nonce. Not
	// implemented yet — the request-side x/crypto/ocsp lacks nonce-extension
	// support, so this is a TODO.
	OCSPNonceRequired

	// OCSPNonceDisabled omits the nonce extension entirely.
	OCSPNonceDisabled
)

// OCSPChecker queries an OCSP responder for cert revocation status.
//
// Per the [feedback-https-client-and-airgap] project rule, OCSPChecker
// always takes a caller-supplied [*http.Client] and propagates
// [context.Context] from Check through to the HTTP layer — production
// callers can wire timeouts, proxies, TLS pinning, and tracing via the
// client. A nil HTTPClient falls back to [http.DefaultClient] for tests; do
// not rely on the fallback in production.
//
// OCSPChecker is safe for concurrent use.
type OCSPChecker struct {
	// HTTPClient executes the OCSP POST. Required in production; nil → DefaultClient.
	HTTPClient *http.Client

	// ResponderURL overrides the AIA (Authority Information Access) URL
	// embedded in the certificate. Useful for caged environments where the
	// public OCSP endpoint isn't reachable.
	ResponderURL string

	// MaxResponseAge rejects responses whose ProducedAt is older than now-MaxResponseAge.
	// Zero disables the check.
	MaxResponseAge time.Duration

	// Clock overrides time.Now for response-age comparisons. Nil → time.Now.
	Clock func() time.Time

	// NoncePolicy is recorded for forward compatibility; see [OCSPNoncePolicy].
	NoncePolicy OCSPNoncePolicy
}

// Check implements [RevocationChecker]. It returns Status=Unknown with the
// failure reason filled in when the responder is unreachable, the response
// is invalid, or the response is older than MaxResponseAge. Network errors
// are returned as the second value so [EvaluateChain] can decide whether to
// fall back to another checker.
//
// Brainpool note: x/crypto/ocsp dispatches signature verification through
// the standard library's ECDSA path, which is curve-agnostic — a Brainpool
// issuer's pubkey verifies a Brainpool-signed response without special
// handling, provided the issuer cert was parsed via [ParseCertificate] (so
// its PublicKey.Curve is set to the Brainpool implementation). Delegated
// responder certs embedded in the OCSP response, however, are parsed by
// x/crypto/ocsp itself via crypto/x509 — those are limited to NIST until
// we add a manual response-cert parser.
func (c *OCSPChecker) Check(ctx context.Context, cert, issuer *x509.Certificate) (*RevocationResult, error) {
	if cert == nil || issuer == nil {
		return nil, fmt.Errorf("gempki: OCSPChecker.Check requires non-nil cert and issuer")
	}
	if err := assertECC(cert.PublicKey); err != nil {
		return nil, fmt.Errorf("gempki: OCSP cert %q: %w", cert.Subject.CommonName, err)
	}
	if err := assertECC(issuer.PublicKey); err != nil {
		return nil, fmt.Errorf("gempki: OCSP issuer %q: %w", issuer.Subject.CommonName, err)
	}

	responderURL := c.ResponderURL
	if responderURL == "" {
		responderURL = pickOCSPURL(cert)
	}
	if responderURL == "" {
		return unknownResult("no OCSP responder URL (AIA missing and no override)"), nil
	}
	if _, err := url.Parse(responderURL); err != nil {
		// A malformed URL is a permanent failure for this cert (not a transient
		// network problem), so we report it as Status=Unknown — the caller's
		// RevocationMode decides whether that's fatal. Returning a non-nil err
		// here would make a Composite checker fall through to the next source,
		// which is the wrong semantics: nobody else can answer for a cert with
		// an invalid AIA either.
		return unknownResult("invalid OCSP responder URL: " + err.Error()), nil //nolint:nilerr // see above
	}

	now := time.Now
	if c.Clock != nil {
		now = c.Clock
	}

	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("gempki: build OCSP request for %q: %w", cert.Subject.CommonName, err)
	}

	respBody, err := c.post(ctx, responderURL, req)
	if err != nil {
		// Network-level errors propagate so a Composite can fall through.
		return nil, fmt.Errorf("gempki: OCSP POST to %s: %w", responderURL, err)
	}

	parsed, err := parseOCSPResponse(respBody, issuer)
	if err != nil {
		// Malformed response from the responder is Status=Unknown rather than
		// a checker error — see the URL-parse path above for the rationale.
		return unknownResult("parse OCSP response: " + err.Error()), nil //nolint:nilerr // see above
	}

	if c.MaxResponseAge > 0 {
		if age := now().Sub(parsed.ProducedAt); age > c.MaxResponseAge {
			return unknownResult(fmt.Sprintf("OCSP response age %s exceeds MaxResponseAge %s",
				age.Truncate(time.Second), c.MaxResponseAge)), nil
		}
	}

	return mapOCSPResponse(parsed, now()), nil
}

// post sends body to url and returns the response body. Honours ctx + the
// configured http.Client.
func (c *OCSPChecker) post(ctx context.Context, urlStr string, body []byte) ([]byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// pickOCSPURL returns the first AIA OCSP URL from cert, or "" if none.
func pickOCSPURL(cert *x509.Certificate) string {
	if len(cert.OCSPServer) == 0 {
		return ""
	}
	return cert.OCSPServer[0]
}

// parseOCSPResponse wraps x/crypto/ocsp.ParseResponse so this package owns
// the type. The Brainpool *issuer* pubkey path works transparently because
// signature verification dispatches through curve-agnostic ecdsa.Verify;
// what x/crypto/ocsp still can't handle is a *delegated responder cert*
// embedded in the response that is itself on a Brainpool curve. That gap
// would need a manual response-cert parser; it is deferred until we see a
// TI deployment where the responder cert isn't the issuer itself.
func parseOCSPResponse(respBytes []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	return ocsp.ParseResponse(respBytes, issuer)
}

// mapOCSPResponse converts an x/crypto/ocsp.Response into our RevocationResult.
func mapOCSPResponse(resp *ocsp.Response, checkedAt time.Time) *RevocationResult {
	r := &RevocationResult{
		Source:    RevocationSourceOCSP,
		CheckedAt: checkedAt,
	}
	switch resp.Status {
	case ocsp.Good:
		r.Status = RevocationStatusGood
	case ocsp.Revoked:
		r.Status = RevocationStatusRevoked
		r.RevokedAt = resp.RevokedAt
		r.Reason = ocspReasonString(resp.RevocationReason)
	default:
		r.Status = RevocationStatusUnknown
		r.Reason = "OCSP status: unknown"
	}
	return r
}

// unknownResult builds a Status=Unknown RevocationResult with a reason. Used
// when we couldn't reach or parse a response — the caller decides how to
// react via [RevocationMode].
func unknownResult(reason string) *RevocationResult {
	return &RevocationResult{
		Status:    RevocationStatusUnknown,
		Source:    RevocationSourceOCSP,
		CheckedAt: time.Now(),
		Reason:    reason,
	}
}

func ocspReasonString(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "keyCompromise"
	case ocsp.CACompromise:
		return "cACompromise"
	case ocsp.AffiliationChanged:
		return "affiliationChanged"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessationOfOperation"
	case ocsp.CertificateHold:
		return "certificateHold"
	case ocsp.RemoveFromCRL:
		return "removeFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ocsp.AACompromise:
		return "aACompromise"
	}
	return fmt.Sprintf("reason(%d)", reason)
}
