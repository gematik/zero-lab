// Package testocsp provides a configurable mock OCSP responder for gempki
// tests. The responder serves OCSP responses over HTTP (httptest.Server),
// signed with an ECDSA key supplied by the test.
//
// Responses are assembled here rather than by x/crypto/ocsp.CreateResponse
// because that rounds producedAt to the minute, refuses Brainpool signers,
// and gives no way to answer with a CertID or timestamps the test chooses —
// and gempki's checker rejects exactly those deviations.
//
// The responder is intended for unit tests. It does NOT enforce request
// validity beyond what is needed to drive gempki's revocation logic.
package testocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

	// ProducedAt, ThisUpdate and NextUpdate override the defaults of now,
	// now and now+24h. NextUpdate is omitted when NoNextUpdate is set.
	ProducedAt   time.Time
	ThisUpdate   time.Time
	NextUpdate   time.Time
	NoNextUpdate bool

	// CertHash, when set, is emitted as the id-isismtt-at-certHash single
	// extension (SHA-256) — see [CertHash] for the matching value.
	CertHash []byte

	// AnswerSerial, when set, replaces the requested serial in the
	// response's CertID, so the answer is about another certificate.
	AnswerSerial *big.Int
}

// CertHash is the certHash value a TI responder would emit for cert.
func CertHash(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
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
// issuer is the CA whose serial numbers will be answered; its name and key
// hashes go into every CertID. signerKey + signerCert sign each response,
// on any ECDSA curve.
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

// The ASN.1 mirrors RFC 6960 §4.2.1; only the fields the mock emits are
// modelled.
type ocspResponse struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
}

type singleResponse struct {
	CertID     certID
	Good       asn1.Flag        `asn1:"tag:0,optional"`
	Revoked    revokedInfo      `asn1:"tag:1,optional"`
	Unknown    asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type certHash struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	Hash          []byte
}

var (
	oidBasicResponse   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidCertHash        = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 13}
)

func (r *Responder) buildResponse(req *ocsp.Request) ([]byte, error) {
	r.mu.RLock()
	e, found := r.entries[req.SerialNumber.String()]
	r.mu.RUnlock()

	now := time.Now().UTC().Truncate(time.Second)
	single := singleResponse{
		Unknown:    true,
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	producedAt := now
	if found {
		switch e.Status {
		case StatusGood:
			single.Unknown = false
			single.Good = true
		case StatusRevoked:
			single.Unknown = false
			single.Revoked = revokedInfo{RevocationTime: e.RevokedAt.UTC(), Reason: asn1.Enumerated(e.Reason)}
			if e.RevokedAt.IsZero() {
				single.Revoked.RevocationTime = now.Add(-time.Hour)
			}
		case StatusUnknown:
		default:
			return nil, fmt.Errorf("testocsp: unknown entry status %d", e.Status)
		}
		if !e.ProducedAt.IsZero() {
			producedAt = e.ProducedAt.UTC()
		}
		if !e.ThisUpdate.IsZero() {
			single.ThisUpdate = e.ThisUpdate.UTC()
		}
		if !e.NextUpdate.IsZero() {
			single.NextUpdate = e.NextUpdate.UTC()
		}
		if e.NoNextUpdate {
			single.NextUpdate = time.Time{}
		}
		if e.CertHash != nil {
			value, err := asn1.Marshal(certHash{
				HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
				Hash:          e.CertHash,
			})
			if err != nil {
				return nil, fmt.Errorf("testocsp: marshal certHash: %w", err)
			}
			single.Extensions = []pkix.Extension{{Id: oidCertHash, Value: value}}
		}
	}

	id, err := r.certID(req, e.AnswerSerial)
	if err != nil {
		return nil, err
	}
	single.CertID = id

	tbs, err := asn1.Marshal(responseData{
		ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: r.SignerCert.RawSubject},
		ProducedAt:  producedAt,
		Responses:   []singleResponse{single},
	})
	if err != nil {
		return nil, fmt.Errorf("testocsp: marshal tbsResponseData: %w", err)
	}
	digest := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, r.SignerKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("testocsp: sign: %w", err)
	}
	basic := basicResponse{
		TBSResponseData:    asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	// Embed the signer cert whenever it's distinct from the issuer — the
	// delegated-responder case real OCSP responders use, and the only way
	// to exercise the embedded-cert parsing path in unit tests.
	if r.Issuer != nil && !r.SignerCert.Equal(r.Issuer) {
		basic.Certificates = []asn1.RawValue{{FullBytes: r.SignerCert.Raw}}
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		return nil, fmt.Errorf("testocsp: marshal BasicOCSPResponse: %w", err)
	}
	return asn1.Marshal(ocspResponse{
		Status:   0,
		Response: responseBytes{ResponseType: oidBasicResponse, Response: basicDER},
	})
}

// certID answers with the hash algorithm the request used, over the
// responder's issuer, as a real responder would.
func (r *Responder) certID(req *ocsp.Request, serial *big.Int) (certID, error) {
	if serial == nil {
		serial = req.SerialNumber
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(r.Issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return certID{}, fmt.Errorf("testocsp: issuer SPKI: %w", err)
	}
	h := req.HashAlgorithm.New()
	h.Write(r.Issuer.RawSubject)
	nameHash := h.Sum(nil)
	h.Reset()
	h.Write(spki.PublicKey.RightAlign())
	keyHash := h.Sum(nil)
	hashOID, ok := hashOIDs[req.HashAlgorithm]
	if !ok {
		return certID{}, fmt.Errorf("testocsp: unsupported request hash %v", req.HashAlgorithm)
	}
	return certID{
		HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue},
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		SerialNumber:   serial,
	}, nil
}

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   {1, 3, 14, 3, 2, 26},
	crypto.SHA256: oidSHA256,
	crypto.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
	crypto.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
}
