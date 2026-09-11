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

	// MaxResponseAge rejects responses whose ProducedAt is older than
	// now-MaxResponseAge, reporting them as Unknown. Zero means
	// [DefaultMaxResponseAge].
	MaxResponseAge time.Duration

	// Clock is "now" for the age check and the CheckedAt stamps. Nil means
	// time.Now.
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

// DefaultMaxResponseAge is how old an OCSP response may be before Check
// reports it as Unknown rather than trusting it.
const DefaultMaxResponseAge = 48 * time.Hour

// Check implements [RevocationChecker]; see the interface for the contract.
// A missing or malformed responder URL and a stale response are reported as
// Status=Unknown, because no other source could answer for such a
// certificate either. Transport failures, undecodable bytes, an
// unauthorized responder and a bad signature are returned as
// [*ValidationError]s with the code that names them.
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

	parsed, err := parseOCSPResponse(respBody, issuer, c.TSLResponders, c.Intermediates, c.Roots)
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

	if age := now().Sub(parsed.ProducedAt); age > maxAge {
		slog.Debug("gempki: OCSP response too old",
			"subject", cert.Subject.CommonName,
			"responder_url", responderURL,
			"age", age.Truncate(time.Second),
			"max_response_age", maxAge)
		return unknownResult(now(), fmt.Sprintf("OCSP response age %s exceeds MaxResponseAge %s",
			age.Truncate(time.Second), maxAge)), nil
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
// Authorization and signature failures come back as [*ValidationError]s
// ([ErrCodeOCSPResponderUntrusted], [ErrCodeOCSPResponseInvalid]) so the
// caller can tell "this response is not to be trusted" from "these bytes
// are not an OCSP response", which is a plain error.
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
