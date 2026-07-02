package gempki

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
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
// client. A nil HTTPClient falls back to a bounded default client for tests; do
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

	// TSLResponders are the OCSP responder certificates the TSL lists
	// (see [OCSPRespondersFromTSL]). Per gemSpec_PKI the TSL is the
	// authoritative directory of OCSP signers for the TI: an embedded
	// responder cert that matches one of these by SKI is trusted to
	// answer for the cert under check, even when it wasn't issued by
	// the cert's own CA (TI's KOMP-CAxx responders answer for SMCB-CAxx
	// cards routinely). This is the TI-spec'd authorization path.
	TSLResponders []*x509.Certificate

	// Intermediates and Roots are the fallback chain-validation path used
	// when the embedded responder cert isn't in TSLResponders. RFC 6960
	// permits a delegated responder that is directly signed by the cert's
	// own issuer; for that path, leave these unset (Check uses the issuer
	// passed at call time).
	Intermediates []*x509.Certificate
	Roots         *TrustStore
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

	parsed, err := parseOCSPResponse(respBody, issuer, c.TSLResponders, c.Intermediates, c.Roots)
	if err != nil {
		slog.Debug("gempki: OCSP parse failed",
			"subject", cert.Subject.CommonName,
			"responder_url", responderURL,
			"err", err)
		// Malformed response from the responder is Status=Unknown rather than
		// a checker error — see the URL-parse path above for the rationale.
		return unknownResult("parse OCSP response: " + err.Error()), nil //nolint:nilerr // see above
	}

	if c.MaxResponseAge > 0 {
		if age := now().Sub(parsed.ProducedAt); age > c.MaxResponseAge {
			slog.Debug("gempki: OCSP response too old",
				"subject", cert.Subject.CommonName,
				"responder_url", responderURL,
				"age", age.Truncate(time.Second),
				"max_response_age", c.MaxResponseAge)
			return unknownResult(fmt.Sprintf("OCSP response age %s exceeds MaxResponseAge %s",
				age.Truncate(time.Second), c.MaxResponseAge)), nil
		}
	}

	result := mapOCSPResponse(parsed, now())
	result.ResponderURL = responderURL
	result.ProducedAt = parsed.ProducedAt
	result.ThisUpdate = parsed.ThisUpdate
	result.NextUpdate = parsed.NextUpdate
	result.RawResponse = respBody
	if parsed.Certificate != nil {
		result.Responder = parsed.Certificate
		result.ResponderName = parsed.Certificate.Subject.CommonName
	} else {
		result.ResponderName = issuer.Subject.CommonName
	}
	slog.Debug("gempki: OCSP check complete",
		"subject", cert.Subject.CommonName,
		"issuer", issuer.Subject.CommonName,
		"responder_url", responderURL,
		"status", result.Status,
		"responder", result.ResponderName,
		"produced_at", result.ProducedAt,
		"this_update", result.ThisUpdate,
		"next_update", result.NextUpdate)
	return result, nil
}

// post sends body to url and returns the response body. Honours ctx + the
// configured http.Client.
func (c *OCSPChecker) post(ctx context.Context, urlStr string, body []byte) ([]byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = defaultHTTPClient
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

// parseOCSPResponse parses an OCSP response, handling delegated responder
// certificates on Brainpool curves that x/crypto/ocsp can't decode through
// its stdlib parser path.
//
// Strategy: walk the DER with [cryptobyte] to locate the embedded certs
// section ([0] EXPLICIT inside BasicOCSPResponse), splice it out, then
// feed the cert-less response to [ocsp.ParseResponse] with issuer=nil —
// that path doesn't try to verify the signature. We then parse each
// embedded cert via [ParseCertificate] (brainpool-aware) and authorize
// the chosen responder cert through one of three paths, in order:
//
//  1. TSL match (gemSpec_PKI): responder SKI matches one of the OCSP
//     responder certs the TSL publishes (`tslResponders`).
//  2. RFC 6960 same-CA: responder signed directly by issuer.
//  3. Chain build: responder chains to a root in `roots` via `extra`.
//
// Then verify the OCSP response signature with the responder's pubkey.
// If there's no embedded cert, the responder is assumed to be issuer
// itself and the response signature is verified directly under issuer.
func parseOCSPResponse(respBytes []byte, issuer *x509.Certificate, tslResponders []*x509.Certificate, extra []*x509.Certificate, roots *TrustStore) (*ocsp.Response, error) {
	stripped, embeddedCerts, err := stripOCSPEmbeddedCerts(respBytes)
	if err != nil {
		return nil, err
	}
	resp, err := ocsp.ParseResponse(stripped, nil)
	if err != nil {
		return nil, err
	}

	if len(embeddedCerts) > 0 {
		var responder *x509.Certificate
		for _, certDER := range embeddedCerts {
			c, perr := ParseCertificate(certDER)
			if perr != nil {
				return nil, fmt.Errorf("parse embedded responder cert: %w", perr)
			}
			if responder == nil {
				responder = c
			}
		}
		resp.Certificate = responder
		if err := authorizeResponderCert(responder, issuer, tslResponders, extra, roots); err != nil {
			return nil, fmt.Errorf("responder cert authorization failed: %w", err)
		}
		if err := resp.CheckSignatureFrom(responder); err != nil {
			return nil, fmt.Errorf("OCSP response signature verification failed under responder cert: %w", err)
		}
		return resp, nil
	}
	if issuer != nil {
		if err := resp.CheckSignatureFrom(issuer); err != nil {
			return nil, fmt.Errorf("OCSP response signature verification failed under issuer: %w", err)
		}
	}
	return resp, nil
}

// authorizeResponderCert decides whether the OCSP responder cert is
// acceptable, in TI/RFC priority order: TSL listing, then RFC 6960
// same-CA, then chain-to-root fallback.
func authorizeResponderCert(responder, issuer *x509.Certificate, tslResponders []*x509.Certificate, extra []*x509.Certificate, roots *TrustStore) error {
	for _, r := range tslResponders {
		if r != nil && bytes.Equal(r.SubjectKeyId, responder.SubjectKeyId) && r.Equal(responder) {
			return nil
		}
	}
	if issuer != nil {
		if err := VerifyCertificateSignature(responder, issuer); err == nil {
			return nil
		}
	}
	if roots == nil {
		return fmt.Errorf("responder %q is not listed in the TSL and not signed by issuer %q; configure OCSPChecker.TSLResponders or .Roots for delegated lookup",
			responder.Subject.CommonName,
			func() string {
				if issuer != nil {
					return issuer.Subject.CommonName
				}
				return "(nil)"
			}())
	}
	pool := append([]*x509.Certificate(nil), extra...)
	if issuer != nil {
		pool = append(pool, issuer)
	}
	if _, err := BuildChain(responder, pool, roots, BuildChainOptions{}); err != nil {
		return fmt.Errorf("build chain for responder %q: %w", responder.Subject.CommonName, err)
	}
	return nil
}

// stripOCSPEmbeddedCerts walks an OCSPResponse DER and returns:
//   - stripped: the same DER with the BasicOCSPResponse's optional certs [0]
//     EXPLICIT section removed (re-encoded with corrected outer lengths)
//   - embeddedCerts: the DER bytes of each Certificate that was in that
//     section, in order
//
// The structure being walked is RFC 6960:
//
//	OCSPResponse ::= SEQUENCE {
//	    responseStatus  OCSPResponseStatus,         -- ENUMERATED
//	    responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }
//	ResponseBytes ::= SEQUENCE {
//	    responseType   OBJECT IDENTIFIER,
//	    response       OCTET STRING }               -- contains BasicOCSPResponse
//	BasicOCSPResponse ::= SEQUENCE {
//	    tbsResponseData    ResponseData,
//	    signatureAlgorithm AlgorithmIdentifier,
//	    signature          BIT STRING,
//	    certs          [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
//
// If there's no responseBytes (error response) or no certs section, the
// original bytes are returned unchanged and embeddedCerts is empty.
func stripOCSPEmbeddedCerts(respBytes []byte) (stripped []byte, embeddedCerts [][]byte, err error) {
	outer := cryptobyte.String(respBytes)
	var ocspResp cryptobyte.String
	if !outer.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed OCSPResponse outer SEQUENCE")
	}

	var statusElem cryptobyte.String
	if !ocspResp.ReadASN1Element(&statusElem, cryptobyte_asn1.ENUM) {
		return nil, nil, fmt.Errorf("missing responseStatus")
	}

	if ocspResp.Empty() {
		// Error response with no responseBytes — nothing to strip.
		return respBytes, nil, nil
	}

	var responseBytesContent cryptobyte.String
	if !ocspResp.ReadASN1(&responseBytesContent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, nil, fmt.Errorf("malformed responseBytes [0] EXPLICIT")
	}
	var rb cryptobyte.String
	if !responseBytesContent.ReadASN1(&rb, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed responseBytes SEQUENCE")
	}
	var respTypeElem cryptobyte.String
	if !rb.ReadASN1Element(&respTypeElem, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return nil, nil, fmt.Errorf("missing responseType")
	}
	var basicRespOctets cryptobyte.String
	if !rb.ReadASN1(&basicRespOctets, cryptobyte_asn1.OCTET_STRING) {
		return nil, nil, fmt.Errorf("missing response OCTET STRING")
	}

	var basicResp cryptobyte.String
	if !basicRespOctets.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed BasicOCSPResponse")
	}
	var tbsElem, sigAlgElem, sigElem cryptobyte.String
	if !basicResp.ReadASN1Element(&tbsElem, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("missing tbsResponseData")
	}
	if !basicResp.ReadASN1Element(&sigAlgElem, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("missing signatureAlgorithm")
	}
	if !basicResp.ReadASN1Element(&sigElem, cryptobyte_asn1.BIT_STRING) {
		return nil, nil, fmt.Errorf("missing signature BIT STRING")
	}

	hasCerts := !basicResp.Empty()
	if !hasCerts {
		return respBytes, nil, nil
	}
	var certsExplicit cryptobyte.String
	if !basicResp.ReadASN1(&certsExplicit, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, nil, fmt.Errorf("malformed certs [0] EXPLICIT")
	}
	var certsSeq cryptobyte.String
	if !certsExplicit.ReadASN1(&certsSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed certs SEQUENCE OF Certificate")
	}
	for !certsSeq.Empty() {
		var certElem cryptobyte.String
		if !certsSeq.ReadASN1Element(&certElem, cryptobyte_asn1.SEQUENCE) {
			return nil, nil, fmt.Errorf("malformed Certificate in certs section")
		}
		embeddedCerts = append(embeddedCerts, []byte(certElem))
	}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(statusElem)
		b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(respTypeElem)
				b.AddASN1(cryptobyte_asn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddBytes(tbsElem)
						b.AddBytes(sigAlgElem)
						b.AddBytes(sigElem)
					})
				})
			})
		})
	})
	stripped, err = b.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("re-encode stripped OCSP response: %w", err)
	}
	return stripped, embeddedCerts, nil
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
