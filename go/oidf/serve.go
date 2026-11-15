// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package oidf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// refreshAfter is how long a signed statement is served before it is signed anew, well inside its lifetime of
	// maxStatementLifetime, so that a signer that fails for a while costs nothing a verifier sees.
	refreshAfter = time.Hour
	// refreshTimeout is the context deadline of a signing a request started. The hooks and the signer take no
	// context, so it is checked between them; a Keys.Sign that hangs is bounded by its own timeouts only.
	refreshTimeout = 5 * time.Second
	// retryBackoff is how long, after a signing that a request started has failed, requests are answered with the last
	// statement before one tries again, so that a failing signer or hook is not called at the rate of requests.
	retryBackoff = time.Minute
	// maxCacheAge bounds the max-age a cache is told to keep a response.
	maxCacheAge = time.Hour

	// entityStatementContentType is the form gematik's FedIdp test suite checks the statement for (FEDM_FD_REG_001).
	entityStatementContentType = "application/entity-statement+jwt;charset=UTF-8"
	signedJwksContentType      = "application/jwk-set+jwt"
)

// served is one signed document as Serve answers with it. It is not changed once stored.
type served struct {
	body      []byte
	etag      string
	issuedAt  time.Time
	expiresAt time.Time
	refreshAt time.Time
	// redirectURIs are those the statement registers; none for the signed JWKS.
	redirectURIs []string
}

func newServed(body []byte, now time.Time) *served {
	sum := sha256.Sum256(body)
	issuedAt := time.Unix(now.Add(-statementBackdate).Unix(), 0)
	return &served{
		body:      body,
		etag:      `"` + hex.EncodeToString(sum[:]) + `"`,
		issuedAt:  issuedAt,
		expiresAt: issuedAt.Add(maxStatementLifetime),
		refreshAt: now.Add(refreshAfter),
	}
}

// sign signs the entity statement and the signed JWK Set anew and serves them from now on. Its caller holds the
// signing token. The hooks and the signer take no context: ctx is checked before each, and cannot cut one short.
func (rp *RelyingParty) sign(ctx context.Context) error {
	// Cleared before the hooks are read, so that a hook added meanwhile leaves the statement stale.
	wasStale := rp.stale.Swap(false)
	statement, jwks, err := rp.signBoth(ctx)
	if err != nil {
		if wasStale {
			rp.stale.Store(true)
		}
		return err
	}
	rp.statement.Store(statement)
	rp.jwks.Store(jwks)
	rp.retryAt.Store(0)
	return nil
}

func (rp *RelyingParty) signBoth(ctx context.Context) (statement, jwks *served, err error) {
	now := rp.now()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	signedStatement, redirectURIs, err := rp.signStatement(now)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	signedJwks, err := rp.signJwks(now)
	if err != nil {
		return nil, nil, err
	}
	statement = newServed(signedStatement, now)
	statement.redirectURIs = redirectURIs
	return statement, newServed(signedJwks, now), nil
}

// Refresh signs the entity statement and the signed JWK Set anew and serves them from now on. A host calls it when what
// its hooks add has changed: gemSpec_IDP_FedMaster A_28857 asks for a new statement on every change. It waits for a
// signing in flight while ctx lets it, and does not wait for retryBackoff. On an error the statement served before
// stays.
func (rp *RelyingParty) Refresh(ctx context.Context) error {
	if rp.signing == nil {
		return errors.New("a relying party not built by New does not sign")
	}
	select {
	case rp.signing <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-rp.signing }()
	return rp.sign(ctx)
}

// dueForSigning reports whether the served documents are missing, old enough to be signed anew, or lack a hook, and
// no failed signing asks to wait.
func (rp *RelyingParty) dueForSigning(now time.Time) bool {
	statement, jwks := rp.statement.Load(), rp.jwks.Load()
	if statement == nil || jwks == nil {
		return true
	}
	if now.UnixNano() < rp.retryAt.Load() {
		return false
	}
	return rp.stale.Load() || !now.Before(statement.refreshAt) || !now.Before(jwks.refreshAt)
}

// refreshFromRequest re-signs on the request that found the documents due, unless another one does already: that one
// and every other request meanwhile are answered with what is served, which stays valid until its exp. The signing
// does not end when the client hangs up, as it serves all requests after it. A failure is retried after retryBackoff.
func (rp *RelyingParty) refreshFromRequest(request context.Context) {
	select {
	case rp.signing <- struct{}{}:
	default:
		return
	}
	defer func() { <-rp.signing }()
	if !rp.dueForSigning(rp.now()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request), refreshTimeout)
	defer cancel()
	err := rp.sign(ctx)
	if err == nil {
		return
	}
	rp.retryAt.Store(rp.now().Add(retryBackoff).UnixNano())
	if rp.cfg != nil && rp.cfg.Logger != nil {
		rp.cfg.Logger.LogAttrs(ctx, slog.LevelError, "signing the entity statement anew failed; the last one is served until it expires",
			slog.Any("error", err))
	}
}

// Serve is the HTTP handler of the entity statement endpoint (gemSpec_IDP_FD A_23034-02). It answers with the statement
// signed before and does no signing of its own, unless the statement is due for signing anew.
func (rp *RelyingParty) Serve(w http.ResponseWriter, r *http.Request) {
	rp.serve(w, r, &rp.statement, entityStatementContentType)
}

// ServeSignedJwks is the HTTP handler of signed_jwks_uri: the ID token and client keys of the relying party as a
// signed JWK Set, with the lifetime of the statement and served as it is.
func (rp *RelyingParty) ServeSignedJwks(w http.ResponseWriter, r *http.Request) {
	rp.serve(w, r, &rp.jwks, signedJwksContentType)
}

// serve answers with a signed document. The body is public and signed, so any cache may keep it: trust comes from
// the signature, not from where the bytes came from. Once the document has expired, because signing it anew has
// failed for as long as it lives, the answer is 503 and never an expired document (servers.md rule 16).
func (rp *RelyingParty) serve(w http.ResponseWriter, r *http.Request, document *atomic.Pointer[served], contentType string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if rp.dueForSigning(rp.now()) {
		rp.refreshFromRequest(r.Context())
	}
	now := rp.now()
	current := document.Load()
	if current == nil || !now.Before(current.expiresAt) {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	header := w.Header()
	header.Set("ETag", current.etag)
	header.Set("Cache-Control", "public, max-age="+strconv.Itoa(cacheAge(now, current.refreshAt)))
	header.Set("Last-Modified", current.issuedAt.UTC().Format(http.TimeFormat))
	if matchesETag(r.Header.Values("If-None-Match"), current.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.Itoa(len(current.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		// An error here is a client that went away; there is nobody left to tell.
		_, _ = w.Write(current.body)
	}
}

// cacheAge is the max-age in seconds until the document is due for signing anew, within [0, maxCacheAge].
func cacheAge(now, refreshAt time.Time) int {
	age := min(refreshAt.Sub(now), maxCacheAge)
	return int(max(age, 0) / time.Second)
}

// matchesETag reports whether an If-None-Match header names the entity tag or is "*". The comparison is weak, as
// RFC 9110 section 13.1.2 has it for If-None-Match: W/ is ignored, the opaque tag is compared exactly.
func matchesETag(headers []string, etag string) bool {
	for _, header := range headers {
		for candidate := range strings.SplitSeq(header, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
				return true
			}
		}
	}
	return false
}
