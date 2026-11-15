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
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testClock is a clock a test moves.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingSigner counts the signatures asked of it and fails while failing is set, as an HSM that is away.
type countingSigner struct {
	crypto.Signer
	count   atomic.Int64
	failing atomic.Bool
}

func (s *countingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.count.Add(1)
	if s.failing.Load() {
		return nil, errors.New("HSM unavailable")
	}
	return s.Signer.Sign(rand, digest, opts)
}

// lockedBuffer is a log sink that is safe for the concurrent requests of a test.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type servingFixture struct {
	rp     *RelyingParty
	clock  *testClock
	signer *countingSigner
	logs   *lockedBuffer
}

// newServingFixture is a relying party built by New on a clock the test moves, with a signer that counts and a logger
// that keeps what it is given.
func newServingFixture(t *testing.T) *servingFixture {
	t.Helper()
	fixture := &servingFixture{clock: &testClock{now: time.Now()}, logs: new(lockedBuffer)}
	cfg := testRelyingPartyConfig(t, newFederationStub(t))
	cfg.Clock = fixture.clock.Now
	cfg.Logger = slog.New(slog.NewTextHandler(fixture.logs, nil))
	keys := newTestKeys(t)
	fixture.signer = &countingSigner{Signer: keys.Sign}
	keys.Sign = fixture.signer
	rp, err := New(t.Context(), cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rp = rp
	return fixture
}

func (f *servingFixture) get(handler http.HandlerFunc, method string, header http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/.well-known/openid-federation", nil)
	maps.Copy(request.Header, header)
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func (f *servingFixture) statement(t *testing.T) []byte {
	t.Helper()
	recorder := f.get(f.rp.Serve, http.MethodGet, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	return recorder.Body.Bytes()
}

// The statement is signed once and then served as bytes: a thousand requests at once cost no signature, so that
// an unauthenticated endpoint cannot keep an HSM busy. Internal invariant of serving, servers.md rule 24.
func TestServeSignsOncePerRefresh(t *testing.T) {
	fixture := newServingFixture(t)
	if n := fixture.signer.count.Load(); n != 2 {
		t.Fatalf("New signed %d times, want the statement and the signed JWKS", n)
	}
	want := fixture.statement(t)
	var wait sync.WaitGroup
	for i := range 1000 {
		wait.Go(func() {
			handler := fixture.rp.Serve
			if i%2 == 1 {
				handler = fixture.rp.ServeSignedJwks
			}
			recorder := fixture.get(handler, http.MethodGet, nil)
			if recorder.Code != http.StatusOK {
				t.Errorf("status = %d", recorder.Code)
			}
			if i%2 == 0 && !bytes.Equal(recorder.Body.Bytes(), want) {
				t.Error("another statement served")
			}
		})
	}
	wait.Wait()
	if n := fixture.signer.count.Load(); n != 2 {
		t.Errorf("%d signatures after the requests, want none more", n-2)
	}
}

// The statement is signed anew after refreshAfter, on the request that finds it due, and not before.
func TestServeReSignsAfterRefreshAfter(t *testing.T) {
	fixture := newServingFixture(t)
	first := fixture.statement(t)
	fixture.clock.Advance(refreshAfter - time.Second)
	if !bytes.Equal(fixture.statement(t), first) || fixture.signer.count.Load() != 2 {
		t.Fatal("signed anew before refreshAfter")
	}
	fixture.clock.Advance(time.Second)
	second := fixture.statement(t)
	if bytes.Equal(second, first) || fixture.signer.count.Load() != 4 {
		t.Fatalf("not signed anew after refreshAfter: %d signatures", fixture.signer.count.Load())
	}
	issuedAt := func(signed []byte) int64 {
		var claims struct{ Iat int64 }
		if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
			t.Fatal(err)
		}
		return claims.Iat
	}
	if delta := issuedAt(second) - issuedAt(first); delta != int64(refreshAfter/time.Second) {
		t.Errorf("iat moved by %d s", delta)
	}
}

// gemSpec_IDP_FedMaster A_28857: a participant issues its statement anew on every change. Refresh does so when what a
// hook adds has changed.
func TestA_28857_RefreshReissuesOnChange(t *testing.T) {
	fixture := newServingFixture(t)
	var mu sync.Mutex
	name := "first"
	fixture.rp.AddEntityStatementHook(func(es *EntityStatement) error {
		mu.Lock()
		defer mu.Unlock()
		es.Metadata.OpenidRelyingParty.ClientName = name
		return nil
	})
	clientName := func() any {
		var claims map[string]any
		if err := json.Unmarshal(unverifiedPayload(t, fixture.statement(t)), &claims); err != nil {
			t.Fatal(err)
		}
		return member(claims, "metadata", "openid_relying_party", "client_name")
	}
	if got := clientName(); got != "first" {
		t.Fatalf("a hook added after New is not in the next statement: client_name %v", got)
	}
	before := fixture.get(fixture.rp.Serve, http.MethodGet, nil).Header().Get("ETag")
	mu.Lock()
	name = "second"
	mu.Unlock()
	if got := clientName(); got != "first" {
		t.Fatalf("signed anew without Refresh: client_name %v", got)
	}
	if err := fixture.rp.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := clientName(); got != "second" {
		t.Errorf("client_name %v after Refresh", got)
	}
	if after := fixture.get(fixture.rp.Serve, http.MethodGet, nil).Header().Get("ETag"); after == before {
		t.Error("the ETag did not change with the statement")
	}
}

// Servers rule 16: a signer that fails degrades within limits. The last statement is served while it is valid, the
// failure goes to the host's logger, and once the statement has expired the answer is 503 with no detail.
func TestServerRule16_AFailingSignerServesTheLastStatementUntilItsExpThen503(t *testing.T) {
	fixture := newServingFixture(t)
	first := fixture.statement(t)
	fixture.signer.failing.Store(true)
	fixture.clock.Advance(refreshAfter)
	if !bytes.Equal(fixture.statement(t), first) {
		t.Fatal("not the last statement")
	}
	if logs := fixture.logs.String(); !strings.Contains(logs, "HSM unavailable") {
		t.Errorf("the failure was not logged: %q", logs)
	}
	fixture.clock.Advance(maxStatementLifetime - refreshAfter - statementBackdate)
	for name, handler := range map[string]http.HandlerFunc{"statement": fixture.rp.Serve, "signed JWKS": fixture.rp.ServeSignedJwks} {
		recorder := fixture.get(handler, http.MethodGet, nil)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status %d after exp", name, recorder.Code)
		}
		if body := recorder.Body.String(); strings.Contains(body, "HSM") || strings.Contains(body, ".") {
			t.Errorf("%s: body %q", name, body)
		}
	}
	fixture.signer.failing.Store(false)
	fixture.clock.Advance(retryBackoff)
	if bytes.Equal(fixture.statement(t), first) {
		t.Error("not signed anew once the signer is back")
	}
}

// Servers rule 24: a failing signer is not called at the rate of requests. After a failed signing, requests get the
// last statement for retryBackoff; then one tries again.
func TestServerRule24_AFailingSignerIsRetriedAfterABackoff(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.signer.failing.Store(true)
	fixture.clock.Advance(refreshAfter)
	var wait sync.WaitGroup
	for range 1000 {
		wait.Go(func() {
			if recorder := fixture.get(fixture.rp.Serve, http.MethodGet, nil); recorder.Code != http.StatusOK {
				t.Errorf("status = %d", recorder.Code)
			}
		})
	}
	wait.Wait()
	if n := fixture.signer.count.Load() - 2; n > 2 {
		t.Errorf("%d signatures asked for by 1000 requests", n)
	}
	logLines := func() int { return strings.Count(fixture.logs.String(), "\n") }
	if n := logLines(); n != 1 {
		t.Errorf("%d log lines", n)
	}
	before := fixture.signer.count.Load()
	fixture.clock.Advance(retryBackoff - time.Second)
	fixture.statement(t)
	if fixture.signer.count.Load() != before {
		t.Error("tried again within retryBackoff")
	}
	fixture.clock.Advance(time.Second)
	fixture.statement(t)
	fixture.statement(t)
	if n := fixture.signer.count.Load() - before; n != 1 || logLines() != 2 {
		t.Errorf("%d attempts and %d log lines after retryBackoff", n, logLines())
	}
}

// Servers rule 16: a relying party that has nothing signed answers 503, never something unsigned.
func TestServerRule16_ARelyingPartyWithNothingSignedAnswers503(t *testing.T) {
	rp := &RelyingParty{keys: Keys{Sign: newTestKey(t), SignKID: "sign-kid"}, entityStatement: &EntityStatement{}}
	recorder := httptest.NewRecorder()
	rp.ServeSignedJwks(recorder, httptest.NewRequest(http.MethodGet, "/jwks", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Header().Get("Content-Type"), "jwt") {
		t.Errorf("content type = %s", recorder.Header().Get("Content-Type"))
	}
}

// Servers rule 17: a signing key that cannot sign, or a statement that cannot be signed, stops the start.
func TestServerRule17_ASignerThatFailsStopsTheStart(t *testing.T) {
	keys := newTestKeys(t)
	keys.Sign = failingSigner{newTestKey(t)}
	if _, err := New(t.Context(), testRelyingPartyConfig(t, newFederationStub(t)), keys); err == nil || !strings.Contains(err.Error(), "HSM unavailable") {
		t.Errorf("err = %v", err)
	}
}

// Requests that come while the statement is signed anew are answered at once with the statement served before; only
// one request signs.
func TestServeDoesNotWaitForASigningInFlight(t *testing.T) {
	fixture := newServingFixture(t)
	var blocking atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	fixture.rp.AddEntityStatementHook(func(*EntityStatement) error {
		if blocking.Load() {
			entered <- struct{}{}
			<-release
		}
		return nil
	})
	if err := fixture.rp.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := fixture.statement(t)
	blocking.Store(true)
	fixture.clock.Advance(refreshAfter)
	done := make(chan []byte)
	go func() {
		recorder := fixture.get(fixture.rp.Serve, http.MethodGet, nil)
		done <- recorder.Body.Bytes()
	}()
	<-entered
	if !bytes.Equal(fixture.statement(t), first) {
		t.Error("a request during the signing did not get the statement served before")
	}
	blocking.Store(false)
	close(release)
	if bytes.Equal(<-done, first) {
		t.Error("the signing request did not get the new statement")
	}
}

// Servers rule 24: the signing that a request starts serves every request after it, so the client of that request
// hanging up does not end it.
func TestServerRule24_AClientHangingUpDoesNotAbortTheSigning(t *testing.T) {
	fixture := newServingFixture(t)
	first := fixture.statement(t)
	fixture.clock.Advance(refreshAfter)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/.well-known/openid-federation", nil)
	recorder := httptest.NewRecorder()
	fixture.rp.Serve(recorder, request)
	if recorder.Code != http.StatusOK || bytes.Equal(recorder.Body.Bytes(), first) {
		t.Errorf("status %d, signed anew: %v", recorder.Code, !bytes.Equal(recorder.Body.Bytes(), first))
	}
}

// Servers rule 24: Refresh waits for a signing in flight only as long as its context lets it.
func TestServerRule24_RefreshEndsWithItsContext(t *testing.T) {
	fixture := newServingFixture(t)
	fixture.rp.signing <- struct{}{}
	defer func() { <-fixture.rp.signing }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := fixture.rp.Refresh(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

// RFC 9110 section 13.1.2: If-None-Match with the current entity tag, in a list, weak or "*", gets 304 and no body.
func TestRFC9110_IfNoneMatchGets304(t *testing.T) {
	fixture := newServingFixture(t)
	etag := fixture.get(fixture.rp.Serve, http.MethodGet, nil).Header().Get("ETag")
	for _, value := range []string{etag, `"other", ` + etag, "*", "W/" + etag} {
		recorder := fixture.get(fixture.rp.Serve, http.MethodGet, http.Header{"If-None-Match": {value}})
		if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 || recorder.Header().Get("ETag") != etag {
			t.Errorf("%s: status %d, %d bytes", value, recorder.Code, recorder.Body.Len())
		}
	}
	if recorder := fixture.get(fixture.rp.Serve, http.MethodGet, http.Header{"If-None-Match": {`"other"`}}); recorder.Code != http.StatusOK {
		t.Errorf("another tag: status %d", recorder.Code)
	}
}

// RFC 9110 section 9.3.2: HEAD gets the headers of GET and no body.
func TestRFC9110_HeadGetsTheHeadersOnly(t *testing.T) {
	fixture := newServingFixture(t)
	get := fixture.get(fixture.rp.Serve, http.MethodGet, nil)
	head := fixture.get(fixture.rp.Serve, http.MethodHead, nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("status %d, %d bytes", head.Code, head.Body.Len())
	}
	for _, name := range []string{"Content-Type", "Content-Length", "ETag", "Cache-Control", "Last-Modified"} {
		if head.Header().Get(name) != get.Header().Get(name) {
			t.Errorf("%s: %q, GET has %q", name, head.Header().Get(name), get.Header().Get(name))
		}
	}
}

// Servers rule 28: the endpoints accept GET and HEAD only; another method gets 405 with Allow.
func TestServerRule28_AnotherMethodGets405(t *testing.T) {
	fixture := newServingFixture(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		for name, handler := range map[string]http.HandlerFunc{"statement": fixture.rp.Serve, "signed JWKS": fixture.rp.ServeSignedJwks} {
			recorder := fixture.get(handler, method, nil)
			if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s: status %d, Allow %q", method, name, recorder.Code, recorder.Header().Get("Allow"))
			}
		}
	}
	if fixture.signer.count.Load() != 2 {
		t.Error("a refused method caused a signature")
	}
}

// RFC 9111 section 5.2.2.1 and RFC 9110 section 8.8: a cache keeps the statement until it is due for signing anew,
// at most an hour; the entity tag is the body's SHA-256 and Last-Modified its iat.
func TestRFC9111_TheResponseIsCachedUntilTheNextSigning(t *testing.T) {
	fixture := newServingFixture(t)
	recorder := fixture.get(fixture.rp.Serve, http.MethodGet, nil)
	body := recorder.Body.Bytes()
	sum := sha256.Sum256(body)
	if etag := recorder.Header().Get("ETag"); etag != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Errorf("ETag = %s", etag)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %s", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %s", got)
	}
	var claims struct{ Iat int64 }
	if err := json.Unmarshal(unverifiedPayload(t, body), &claims); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Header().Get("Last-Modified"); got != time.Unix(claims.Iat, 0).UTC().Format(http.TimeFormat) {
		t.Errorf("Last-Modified = %s", got)
	}
	fixture.clock.Advance(30 * time.Minute)
	if got := fixture.get(fixture.rp.ServeSignedJwks, http.MethodGet, nil).Header().Get("Cache-Control"); got != "public, max-age=1800" {
		t.Errorf("Cache-Control half an hour later = %s", got)
	}
}

// Servers rule 14: serving writes no log line per request, to the host's logger or the process default.
func TestServerRule14_ServingTheSignedJwksLogsNothing(t *testing.T) {
	fixture := newServingFixture(t)
	defaults := new(lockedBuffer)
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, handler := range []http.HandlerFunc{fixture.rp.Serve, fixture.rp.ServeSignedJwks} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "192.0.2.1:1234"
		handler(httptest.NewRecorder(), request)
	}
	if logs := fixture.logs.String() + defaults.String(); logs != "" {
		t.Errorf("logged: %s", logs)
	}
}

// fedmStatement is the relying party's statement as gematik's FedIdp test suite fetches it, with its JOSE header and
// claims read as JSON.
func fedmStatement(t *testing.T) (recorder *httptest.ResponseRecorder, header, claims map[string]any, rp *RelyingParty) {
	t.Helper()
	fixture := newServingFixture(t)
	recorder = fixture.get(fixture.rp.Serve, http.MethodGet, nil)
	parts := strings.Split(recorder.Body.String(), ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", recorder.Body)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(unverifiedPayload(t, recorder.Body.Bytes()), &claims); err != nil {
		t.Fatal(err)
	}
	return recorder, header, claims, fixture.rp
}

// FEDM_FD_REG_001 (gematik app-FedIdpTestsuite, fachdienstRegistration.feature): the statement is answered with 200
// and the Content-Type application/entity-statement+jwt;charset=UTF-8.
func TestFEDM_FD_REG_001_TheResponseIsAnEntityStatement(t *testing.T) {
	recorder, _, _, _ := fedmStatement(t)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/entity-statement+jwt;charset=UTF-8" {
		t.Errorf("status %d, Content-Type %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}

// FEDM_FD_REG_002: the JWS header has alg ES256, a kid and typ entity-statement+jwt.
func TestFEDM_FD_REG_002_TheHeaderNamesES256AKidAndTheType(t *testing.T) {
	_, header, _, _ := fedmStatement(t)
	if header["alg"] != "ES256" || header["kid"] == "" || header["kid"] == nil || header["typ"] != "entity-statement+jwt" {
		t.Errorf("header = %v", header)
	}
}

// FEDM_FD_REG_003: the claims hold iss and sub as http(s) URLs, iat, exp, jwks, authority_hints with the federation
// master first, and metadata.
func TestFEDM_FD_REG_003_TheClaimsAreThoseOfAnEntityConfiguration(t *testing.T) {
	_, _, claims, rp := fedmStatement(t)
	for _, name := range []string{"iss", "sub"} {
		if value, _ := claims[name].(string); !strings.HasPrefix(value, "http") {
			t.Errorf("%s = %v", name, claims[name])
		}
	}
	for _, name := range []string{"iat", "exp", "jwks", "authority_hints", "metadata"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("%s missing", name)
		}
	}
	if hints, _ := claims["authority_hints"].([]any); len(hints) == 0 || hints[0] != rp.cfg.FedMasterURL {
		t.Errorf("authority_hints = %v", claims["authority_hints"])
	}
}

// FEDM_FD_REG_004: metadata holds openid_relying_party with the values the federation registers, and
// federation_entity.
func TestFEDM_FD_REG_004_TheMetadataIsThatOfARegisteredRelyingParty(t *testing.T) {
	_, _, claims, _ := fedmStatement(t)
	if _, ok := member(claims, "metadata", "federation_entity").(map[string]any); !ok {
		t.Errorf("federation_entity = %v", member(claims, "metadata", "federation_entity"))
	}
	metadata, _ := member(claims, "metadata", "openid_relying_party").(map[string]any)
	want := map[string]string{ //nolint:gosec // token_endpoint_auth_method names an authentication method, not a credential
		"response_types":                        `["code"]`,
		"client_registration_types":             `["automatic"]`,
		"grant_types":                           `["authorization_code"]`,
		"require_pushed_authorization_requests": `true`,
		"token_endpoint_auth_method":            `"self_signed_tls_client_auth"`,
		"id_token_signed_response_alg":          `"ES256"`,
		"id_token_encrypted_response_alg":       `"ECDH-ES"`,
		"id_token_encrypted_response_enc":       `"A256GCM"`,
	}
	for name, value := range want {
		got, err := json.Marshal(metadata[name])
		if err != nil || string(got) != value {
			t.Errorf("%s = %s, want %s", name, got, value)
		}
	}
	for _, name := range []string{"client_name", "scope"} {
		if value, _ := metadata[name].(string); value == "" {
			t.Errorf("%s = %v", name, metadata[name])
		}
	}
	for _, name := range []string{"redirect_uris", "default_acr_values"} {
		if values, _ := metadata[name].([]any); len(values) == 0 {
			t.Errorf("%s = %v", name, metadata[name])
		}
	}
}

// FEDM_FD_REG_005: the federation master registers the key under the statement's header kid; the suite expects it in
// the master's statement about the relying party with use, kid, kty EC, crv P-256, x and y. That key is what the
// relying party publishes under that kid.
func TestFEDM_FD_REG_005_TheSigningKeyIsAP256KeyWithUse(t *testing.T) {
	_, header, claims, _ := fedmStatement(t)
	keys, _ := member(claims, "jwks", "keys").([]any)
	var found map[string]any
	for _, key := range keys {
		if key, _ := key.(map[string]any); key["kid"] == header["kid"] {
			found = key
		}
	}
	if found == nil || found["use"] == nil || found["kty"] != "EC" || found["crv"] != "P-256" || found["x"] == nil || found["y"] == nil {
		t.Errorf("key under %v = %v", header["kid"], found)
	}
}

// BenchmarkServe measures a request for the entity statement, which signs nothing once the statement is signed.
func BenchmarkServe(b *testing.B) {
	rp := literalRelyingParty(b, newTestKey(b))
	if err := rp.sign(b.Context()); err != nil {
		b.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation", nil)
	b.ReportAllocs()
	for b.Loop() {
		rp.Serve(httptest.NewRecorder(), request)
	}
}
