package gempki

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
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

// OCSPChecker queries an OCSP responder for a certificate's revocation
// status. It is the one [RevocationChecker].
//
// The caller supplies the [*http.Client]; timeouts, proxies, TLS pinning and
// tracing all live there, and Check threads its context through to it.
//
// OCSPChecker is safe for concurrent use.
type OCSPChecker struct {
	// HTTPClient executes the OCSP POST. Required.
	HTTPClient *http.Client

	// ResponderURL overrides the AIA (Authority Information Access) URL
	// embedded in the certificate. Useful for caged environments where the
	// public OCSP endpoint isn't reachable.
	ResponderURL string

	// MaxResponseAge is how far producedAt may lie in the past before the
	// response is reported as Unknown. TI responders sign every response
	// on demand, so the default is the same tight window the gematik
	// reference implementation applies; raise it when responses are
	// served from a cache. Zero means [DefaultMaxResponseAge].
	MaxResponseAge time.Duration

	// ClockTolerance is the skew allowed between the responder's clock
	// and ours: thisUpdate and producedAt may lie this far in the future
	// and nextUpdate this far in the past. Zero means
	// [DefaultClockTolerance].
	ClockTolerance time.Duration

	// RequireCertHash rejects a response that carries no certHash
	// extension. gemSpec_PKI mandates the extension for TI responders;
	// a certHash that is present is verified regardless of this flag.
	RequireCertHash bool

	// Clock is "now" for the time-window checks and the CheckedAt stamps.
	// Nil means time.Now.
	Clock func() time.Time

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

// DefaultClockTolerance is the clock skew TUC_PKI_006 grants an OCSP
// responder (gemSpec_PKI, 37.5 s); the gematik reference implementation
// applies the same value to producedAt in the past, hence
// [DefaultMaxResponseAge].
const DefaultClockTolerance = 37500 * time.Millisecond

// DefaultMaxResponseAge is how old an OCSP response may be before Check
// reports it as Unknown rather than trusting it.
const DefaultMaxResponseAge = DefaultClockTolerance

// Check implements [RevocationChecker]; see the interface for the contract.
// A missing or malformed responder URL and a response outside the time
// window (MaxResponseAge, ClockTolerance) are reported as Status=Unknown,
// because no other source could answer for such a certificate either.
// Transport failures, undecodable bytes, an unauthorized responder, a bad
// signature, a CertID that does not name cert under issuer and a certHash
// that does not match cert are returned as [*ValidationError]s with the
// code that names them.
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
	if c.HTTPClient == nil {
		return nil, fmt.Errorf("gempki: OCSPChecker requires an HTTPClient")
	}
	now := time.Now
	if c.Clock != nil {
		now = c.Clock
	}
	maxAge := c.MaxResponseAge
	if maxAge <= 0 {
		maxAge = DefaultMaxResponseAge
	}
	skew := c.ClockTolerance
	if skew <= 0 {
		skew = DefaultClockTolerance
	}

	responderURL := c.ResponderURL
	if responderURL == "" {
		responderURL = pickOCSPURL(cert)
	}
	if responderURL == "" {
		return unknownResult(now(), "no OCSP responder URL (AIA missing and no override)"), nil
	}
	if _, err := url.Parse(responderURL); err != nil {
		return unknownResult(now(), "invalid OCSP responder URL: "+err.Error()), nil //nolint:nilerr // reported as Unknown by design
	}

	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("gempki: build OCSP request for %q: %w", cert.Subject.CommonName, err)
	}

	respBody, err := c.post(ctx, responderURL, req)
	if err != nil {
		return nil, &ValidationError{
			Code:    ErrCodeOCSPUnavailable,
			Subject: cert.Subject.CommonName,
			Message: "OCSP responder " + responderURL + " unreachable",
			Cause:   err,
		}
	}

	parsed, err := parseOCSPResponse(respBody, cert, issuer, c.TSLResponders, c.Intermediates, c.Roots)
	if err == nil {
		err = verifyCertHash(parsed, cert, c.RequireCertHash)
	}
	if err != nil {
		slog.Debug("gempki: OCSP response rejected",
			"subject", cert.Subject.CommonName,
			"responder_url", responderURL,
			"err", err)
		var ve *ValidationError
		if errors.As(err, &ve) {
			ve.Subject = cert.Subject.CommonName
			return nil, ve
		}
		return nil, &ValidationError{
			Code:    ErrCodeOCSPUnavailable,
			Subject: cert.Subject.CommonName,
			Message: "OCSP response from " + responderURL + " could not be decoded",
			Cause:   err,
		}
	}

	if reason := checkResponseTimes(parsed, now(), maxAge, skew); reason != "" {
		slog.Debug("gempki: OCSP response outside time window",
			"subject", cert.Subject.CommonName,
			"responder_url", responderURL,
			"reason", reason,
			"produced_at", parsed.ProducedAt,
			"this_update", parsed.ThisUpdate,
			"next_update", parsed.NextUpdate)
		return unknownResult(now(), reason), nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// checkResponseTimes applies the TUC_PKI_006 time window and returns the
// reason a response falls outside it, or "" when it is acceptable:
// producedAt within [now-maxAge, now+skew], thisUpdate at most skew in
// the future, nextUpdate (if present) at most skew in the past.
func checkResponseTimes(resp *ocsp.Response, now time.Time, maxAge, skew time.Duration) string {
	if age := now.Sub(resp.ProducedAt); age > maxAge {
		return fmt.Sprintf("OCSP response age %s exceeds MaxResponseAge %s", age.Truncate(time.Second), maxAge)
	}
	if ahead := resp.ProducedAt.Sub(now); ahead > skew {
		return fmt.Sprintf("OCSP producedAt lies %s in the future", ahead.Truncate(time.Second))
	}
	if ahead := resp.ThisUpdate.Sub(now); ahead > skew {
		return fmt.Sprintf("OCSP thisUpdate lies %s in the future", ahead.Truncate(time.Second))
	}
	if !resp.NextUpdate.IsZero() {
		if behind := now.Sub(resp.NextUpdate); behind > skew {
			return fmt.Sprintf("OCSP nextUpdate passed %s ago", behind.Truncate(time.Second))
		}
	}
	return ""
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
//
// Before any of that the CertID of the single response is compared with
// the one we asked about (serial, issuer name hash and issuer key hash
// under the responder's hash algorithm), so a replayed answer for another
// certificate of the same CA cannot stand in for this one.
//
// Authorization, signature and CertID failures come back as
// [*ValidationError]s ([ErrCodeOCSPResponderUntrusted],
// [ErrCodeOCSPResponseInvalid]) so the caller can tell "this response is
// not to be trusted" from "these bytes are not an OCSP response", which
// is a plain error.
func parseOCSPResponse(respBytes []byte, cert, issuer *x509.Certificate, tslResponders []*x509.Certificate, extra []*x509.Certificate, roots *TrustStore) (*ocsp.Response, error) {
	split, err := splitOCSPResponse(respBytes)
	if err != nil {
		return nil, err
	}
	resp, err := ocsp.ParseResponse(split.stripped, nil)
	if err != nil {
		return nil, err
	}
	if cert != nil && issuer != nil {
		if err := verifyCertID(split.tbs, cert, issuer); err != nil {
			return nil, &ValidationError{
				Code:    ErrCodeOCSPResponseInvalid,
				Message: "OCSP response does not answer for this certificate",
				Cause:   err,
			}
		}
	}
	embeddedCerts := split.certs

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
			return nil, &ValidationError{
				Code:    ErrCodeOCSPResponderUntrusted,
				Message: "OCSP responder " + responder.Subject.CommonName + " is not authorized to answer",
				Cause:   err,
			}
		}
		if err := resp.CheckSignatureFrom(responder); err != nil {
			return nil, &ValidationError{
				Code:    ErrCodeOCSPResponseInvalid,
				Message: "OCSP response signature does not verify under responder " + responder.Subject.CommonName,
				Cause:   err,
			}
		}
		return resp, nil
	}
	if issuer != nil {
		if err := resp.CheckSignatureFrom(issuer); err != nil {
			return nil, &ValidationError{
				Code:    ErrCodeOCSPResponseInvalid,
				Message: "OCSP response signature does not verify under issuer " + issuer.Subject.CommonName,
				Cause:   err,
			}
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
		if err := verifyCertificateSignature(responder, issuer); err == nil {
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
	if _, err := BuildChain(responder, pool, roots); err != nil {
		return fmt.Errorf("build chain for responder %q: %w", responder.Subject.CommonName, err)
	}
	return nil
}

// ocspSplit is what [splitOCSPResponse] takes an OCSPResponse apart into.
type ocspSplit struct {
	// stripped is the response DER with the BasicOCSPResponse's optional
	// certs [0] EXPLICIT section removed (outer lengths re-encoded).
	stripped []byte
	// tbs is the tbsResponseData element, the part the CertID lives in.
	tbs []byte
	// certs holds the DER of each Certificate from the certs section.
	certs [][]byte
}

// splitOCSPResponse walks an OCSPResponse DER and separates the parts
// [parseOCSPResponse] needs.
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
// original bytes are returned unchanged and certs is empty.
func splitOCSPResponse(respBytes []byte) (ocspSplit, error) {
	var empty ocspSplit
	outer := cryptobyte.String(respBytes)
	var ocspResp cryptobyte.String
	if !outer.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) {
		return empty, fmt.Errorf("malformed OCSPResponse outer SEQUENCE")
	}

	var statusElem cryptobyte.String
	if !ocspResp.ReadASN1Element(&statusElem, cryptobyte_asn1.ENUM) {
		return empty, fmt.Errorf("missing responseStatus")
	}

	if ocspResp.Empty() {
		// Error response with no responseBytes — nothing to strip.
		return ocspSplit{stripped: respBytes}, nil
	}

	var responseBytesContent cryptobyte.String
	if !ocspResp.ReadASN1(&responseBytesContent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return empty, fmt.Errorf("malformed responseBytes [0] EXPLICIT")
	}
	var rb cryptobyte.String
	if !responseBytesContent.ReadASN1(&rb, cryptobyte_asn1.SEQUENCE) {
		return empty, fmt.Errorf("malformed responseBytes SEQUENCE")
	}
	var respTypeElem cryptobyte.String
	if !rb.ReadASN1Element(&respTypeElem, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return empty, fmt.Errorf("missing responseType")
	}
	var basicRespOctets cryptobyte.String
	if !rb.ReadASN1(&basicRespOctets, cryptobyte_asn1.OCTET_STRING) {
		return empty, fmt.Errorf("missing response OCTET STRING")
	}

	var basicResp cryptobyte.String
	if !basicRespOctets.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
		return empty, fmt.Errorf("malformed BasicOCSPResponse")
	}
	var tbsElem, sigAlgElem, sigElem cryptobyte.String
	if !basicResp.ReadASN1Element(&tbsElem, cryptobyte_asn1.SEQUENCE) {
		return empty, fmt.Errorf("missing tbsResponseData")
	}
	if !basicResp.ReadASN1Element(&sigAlgElem, cryptobyte_asn1.SEQUENCE) {
		return empty, fmt.Errorf("missing signatureAlgorithm")
	}
	if !basicResp.ReadASN1Element(&sigElem, cryptobyte_asn1.BIT_STRING) {
		return empty, fmt.Errorf("missing signature BIT STRING")
	}

	if basicResp.Empty() {
		return ocspSplit{stripped: respBytes, tbs: []byte(tbsElem)}, nil
	}
	var certsExplicit cryptobyte.String
	if !basicResp.ReadASN1(&certsExplicit, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return empty, fmt.Errorf("malformed certs [0] EXPLICIT")
	}
	var certsSeq cryptobyte.String
	if !certsExplicit.ReadASN1(&certsSeq, cryptobyte_asn1.SEQUENCE) {
		return empty, fmt.Errorf("malformed certs SEQUENCE OF Certificate")
	}
	var embeddedCerts [][]byte
	for !certsSeq.Empty() {
		var certElem cryptobyte.String
		if !certsSeq.ReadASN1Element(&certElem, cryptobyte_asn1.SEQUENCE) {
			return empty, fmt.Errorf("malformed Certificate in certs section")
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
	stripped, err := b.Bytes()
	if err != nil {
		return empty, fmt.Errorf("re-encode stripped OCSP response: %w", err)
	}
	return ocspSplit{stripped: stripped, tbs: []byte(tbsElem), certs: embeddedCerts}, nil
}

// mapOCSPResponse converts an x/crypto/ocsp.Response into our RevocationResult.
func mapOCSPResponse(resp *ocsp.Response, checkedAt time.Time) *RevocationResult {
	r := &RevocationResult{CheckedAt: checkedAt}
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

// unknownResult is a Status=Unknown verdict for a certificate no responder
// can be asked about; the caller's [RevocationMode] decides what that means.
func unknownResult(now time.Time, reason string) *RevocationResult {
	return &RevocationResult{
		Status:    RevocationStatusUnknown,
		CheckedAt: now,
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
