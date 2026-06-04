// Package testocsp provides a configurable mock OCSP responder for gempki
// tests. The responder serves OCSP responses over HTTP (httptest.Server),
// signed with an ECDSA key supplied by the test.
//
// Phase 0 scope: NIST P-256 / P-384 OCSP signer keys only, and no nonce
// echo (the parsed ocsp.Request does not expose extensions; manual ASN.1
// extraction lands in Phase 4 alongside the production OCSPChecker, where
// nonce policy is actually consumed). Brainpool OCSP signing also lands in
// Phase 4 because golang.org/x/crypto/ocsp does not handle Brainpool signers.
//
// The responder is intended for unit tests. It does NOT enforce request
// validity beyond what is needed to drive gempki's revocation logic.
package testocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// EntryStatus matches the canonical OCSP single-response statuses.
type EntryStatus int

const (
	StatusGood EntryStatus = iota
	StatusRevoked
	StatusUnknown
)

// Entry is one configured response for a specific certificate serial.
type Entry struct {
	Status    EntryStatus
	RevokedAt time.Time // honored when Status == StatusRevoked
	Reason    int       // RFC 5280 revocation reason; 0 = unspecified
}

// NonceMode is reserved for future nonce-policy testing. In Phase 0 the
// responder always omits a nonce extension; the mode is recorded for API
// stability so Phase 4 callers don't need to change their setup.
type NonceMode int

const (
	NonceEcho NonceMode = iota
	NonceIgnore
	NonceMismatch
)

// Responder is a stateful mock OCSP server.
//
// Concurrent-safe for entry mutation; HTTP handler reads under RLock.
type Responder struct {
	Server     *httptest.Server
	URL        string
	Issuer     *x509.Certificate
	SignerKey  *ecdsa.PrivateKey
	SignerCert *x509.Certificate

	mu        sync.RWMutex
	entries   map[string]Entry
	nonceMode NonceMode
	delay     time.Duration

	failAfterN atomic.Int32
	reqCount   atomic.Int32
}

// NewResponder starts a mock OCSP responder.
//
// issuer is the CA whose serial numbers will be answered.
// signerKey + signerCert sign each response. The signer's curve must be NIST
// P-256 or P-384 — see the package doc for why Brainpool isn't supported yet.
//
// The returned responder is registered with t.Cleanup, so callers don't need
// to close it explicitly.
func NewResponder(t *testing.T, issuer *x509.Certificate, signerKey *ecdsa.PrivateKey, signerCert *x509.Certificate) *Responder {
	t.Helper()
	if issuer == nil {
		t.Fatal("testocsp: issuer is required")
	}
	if signerKey == nil || signerCert == nil {
		t.Fatal("testocsp: signerKey and signerCert are required")
	}
	switch signerKey.Curve {
	case elliptic.P256(), elliptic.P384():
		// OK — golang.org/x/crypto/ocsp can sign with these.
	default:
		t.Fatalf("testocsp: signer curve %q not supported in Phase 0; brainpool OCSP signing arrives in Phase 4",
			signerKey.Curve.Params().Name)
	}

	r := &Responder{
		Issuer:     issuer,
		SignerKey:  signerKey,
		SignerCert: signerCert,
		entries:    make(map[string]Entry),
	}
	r.Server = httptest.NewServer(http.HandlerFunc(r.handle))
	r.URL = r.Server.URL
	t.Cleanup(r.Server.Close)
	return r
}

// Set configures the response for a specific certificate serial.
func (r *Responder) Set(serial *big.Int, e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[serial.String()] = e
}

// SetNonceMode is a placeholder until Phase 4 wires nonce extension handling.
func (r *Responder) SetNonceMode(m NonceMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nonceMode = m
}

// SetDelay artificially delays every response by d. Useful for context-cancel
// tests.
func (r *Responder) SetDelay(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delay = d
}

// SetFailAfter makes the Nth request and every subsequent request return
// HTTP 500. n <= 0 disables the behaviour.
func (r *Responder) SetFailAfter(n int) {
	r.failAfterN.Store(int32(n)) //nolint:gosec // test-only, bounded N
}

// RequestCount returns the total number of HTTP requests served so far.
func (r *Responder) RequestCount() int {
	return int(r.reqCount.Load())
}

func (r *Responder) handle(w http.ResponseWriter, req *http.Request) {
	count := r.reqCount.Add(1)

	r.mu.RLock()
	delay := r.delay
	r.mu.RUnlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-req.Context().Done():
			http.Error(w, "client cancelled", http.StatusRequestTimeout)
			return
		}
	}

	if failAfter := r.failAfterN.Load(); failAfter > 0 && count >= failAfter {
		http.Error(w, "configured failure", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, "parse OCSP request: "+err.Error(), http.StatusBadRequest)
		return
	}

	respBytes, err := r.buildResponse(ocspReq)
	if err != nil {
		http.Error(w, "build response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(respBytes)
}

func (r *Responder) buildResponse(req *ocsp.Request) ([]byte, error) {
	r.mu.RLock()
	e, found := r.entries[req.SerialNumber.String()]
	r.mu.RUnlock()

	now := time.Now()
	tmpl := ocsp.Response{
		Status:       ocsp.Unknown,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(24 * time.Hour),
		IssuerHash:   req.HashAlgorithm,
	}
	if found {
		switch e.Status {
		case StatusGood:
			tmpl.Status = ocsp.Good
		case StatusRevoked:
			tmpl.Status = ocsp.Revoked
			tmpl.RevokedAt = e.RevokedAt
			if tmpl.RevokedAt.IsZero() {
				tmpl.RevokedAt = now.Add(-time.Hour)
			}
			tmpl.RevocationReason = e.Reason
		case StatusUnknown:
			tmpl.Status = ocsp.Unknown
		default:
			return nil, fmt.Errorf("testocsp: unknown entry status %d", e.Status)
		}
	}

	return ocsp.CreateResponse(r.Issuer, r.SignerCert, tmpl, r.SignerKey)
}
