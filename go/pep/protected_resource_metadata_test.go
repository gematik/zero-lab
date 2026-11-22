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

package pep

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
)

// RFC 9728 Section 3.1: the well-known segment goes between the host and the resource's path and query, a
// terminating slash after the host removed first.
func TestRFC9728_3_1_TheMetadataURLIsDerivedFromTheResource(t *testing.T) {
	for resource, want := range map[string]string{
		"https://rs.example":               "https://rs.example/.well-known/oauth-protected-resource",
		"https://rs.example/":              "https://rs.example/.well-known/oauth-protected-resource",
		"https://rs.example:8443/api/v1":   "https://rs.example:8443/.well-known/oauth-protected-resource/api/v1",
		"https://rs.example/api/":          "https://rs.example/.well-known/oauth-protected-resource/api/",
		"https://rs.example/api?tenant=a1": "https://rs.example/.well-known/oauth-protected-resource/api?tenant=a1",
		"http://127.0.0.1:8010":            "http://127.0.0.1:8010/.well-known/oauth-protected-resource",
	} {
		got, err := ProtectedResourceMetadataURL(resource)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", resource, got, err, want)
		}
	}
	for _, resource := range []string{"", "rs.example", "urn:example:rs", "https://user@rs.example", "https://rs.example/#frag", "ftp://rs.example"} {
		if got, err := ProtectedResourceMetadataURL(resource); err == nil {
			t.Errorf("%q: derived %q", resource, got)
		}
	}
}

func metadataPEP(t *testing.T, resource string, keys *jose.JSONWebKeySet) *PEP {
	t.Helper()
	p, err := NewBuilder().Resource(resource).WithJWKSet(keys).WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func challengeOf(t *testing.T, p *PEP, enforcer Enforcer, authorization string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://rs.example/api/v1/items", http.NoBody)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	p.GuardedHandlerFunc(enforcer, func(http.ResponseWriter, *http.Request) {})(w, r)
	return w.Code, w.Header().Get("WWW-Authenticate")
}

// RFC 9728 Section 5.1: every 401 challenge of the PEP names the resource's metadata in resource_metadata, as an
// auth-param after those of the scheme, whether the client sent no credentials or invalid ones, under Bearer and
// DPoP, for a resource with and without a path.
func TestRFC9728_5_1_A401ChallengeNamesTheResourceMetadata(t *testing.T) {
	keys := &jose.JSONWebKeySet{}
	for resource, metadata := range map[string]string{
		"https://rs.example":        `resource_metadata="https://rs.example/.well-known/oauth-protected-resource"`,
		"https://rs.example/api/v1": `resource_metadata="https://rs.example/.well-known/oauth-protected-resource/api/v1"`,
	} {
		p := metadataPEP(t, resource, keys)
		for _, c := range []struct {
			name, authorization, want string
			enforcer                  Enforcer
		}{
			{"Bearer without credentials", "", `Bearer ` + metadata, &EnforcerAuthorizationBearer{}},
			{"Bearer invalid token", "Bearer a.b.c", `Bearer error="invalid_token", error_description="invalid access token", ` + metadata, &EnforcerAuthorizationBearer{}},
			{"DPoP without credentials", "", `DPoP algs="ES256", ` + metadata, &EnforcerAuthorizationDPoP{}},
			{"DPoP invalid token", "DPoP a.b.c", `DPoP error="invalid_token", error_description="invalid access token", algs="ES256", ` + metadata, &EnforcerAuthorizationDPoP{}},
		} {
			t.Run(resource+"/"+c.name, func(t *testing.T) {
				status, challenge := challengeOf(t, p, c.enforcer, c.authorization)
				if status != http.StatusUnauthorized || challenge != c.want {
					t.Errorf("%d %s; want 401 %s", status, challenge, c.want)
				}
			})
		}
	}
}

// RFC 9728 Section 5.1 is about the 401 that sends a client to the authorization server; a 403 for a token the
// client has carries no resource_metadata.
func TestRFC9728_5_1_A403CarriesNoResourceMetadata(t *testing.T) {
	p := metadataPEP(t, "https://rs.example", &jose.JSONWebKeySet{})
	status, challenge := challengeOf(t, p, &EnforcerDeny{}, "")
	if status != http.StatusForbidden || challenge != "" {
		t.Errorf("%d %q", status, challenge)
	}
}

// RFC 9728 Section 5.1: a deployment that serves the metadata elsewhere names its URL; one a quoted-string cannot
// carry unescaped, or not absolute, does not build.
func TestRFC9728_5_1_TheResourceMetadataURLCanBeConfigured(t *testing.T) {
	build := func(metadataURL string) (*PEP, error) {
		return NewBuilder().Resource("https://rs.example").ResourceMetadataURL(metadataURL).
			WithJWKSet(&jose.JSONWebKeySet{}).WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	}
	p, err := build("https://meta.example/rs")
	if err != nil {
		t.Fatal(err)
	}
	if _, challenge := challengeOf(t, p, &EnforcerAuthorizationBearer{}, ""); challenge != `Bearer resource_metadata="https://meta.example/rs"` {
		t.Errorf("challenge %s", challenge)
	}
	for _, bad := range []string{"https://meta.example/a\"b", `https://meta.example/a\b`, "https://meta.example/a b", "/relative", "https://meta.example/ä"} {
		if _, err := build(bad); err == nil {
			t.Errorf("%q: built", bad)
		}
	}
}

// RFC 9728 Section 2: members a profile adds, such as zeta_asl_use, follow the typed ones in a fixed order, and
// none of them can replace a typed member.
func TestRFC9728_2_AddedMembersAreEncodedInOrderAndCannotReplaceTypedOnes(t *testing.T) {
	doc := ProtectedResourceMetadata{
		Resource:             "https://rs.example",
		AuthorizationServers: []string{"https://as.example"},
		Extra: map[string]jsontext.Value{
			"zeta_asl_use": jsontext.Value(`"required"`),
			"a_member":     jsontext.Value(`{"b":1}`),
		},
	}
	got, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"resource":"https://rs.example","authorization_servers":["https://as.example"],"a_member":{"b":1},"zeta_asl_use":"required"}`; string(got) != want {
		t.Errorf("%s\nwant %s", got, want)
	}
	doc.Extra["resource"] = jsontext.Value(`"https://evil.example"`)
	if out, err := json.Marshal(doc, json.Deterministic(true)); err == nil {
		t.Errorf("a typed member was replaced: %s", out)
	}
}

func serveMetadata(t *testing.T, h http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, "https://api.example.com/.well-known/oauth-protected-resource", http.NoBody))
	return w
}

// RFC 9728 Sections 2 and 3.2: the handler answers GET with the document as application/json, the members added
// after the typed ones in a fixed order, and HEAD with its headers alone.
func TestRFC9728_3_2_TheMetadataIsServedAsJSON(t *testing.T) {
	h, err := NewProtectedResourceMetadataHandler(ProtectedResourceMetadata{
		Resource:               "https://api.example.com",
		AuthorizationServers:   []string{"https://as.example.com"},
		ScopesSupported:        []string{"epa.read", "epa.write"},
		BearerMethodsSupported: []string{"header"},
		Extra:                  map[string]jsontext.Value{"zeta_asl_use": jsontext.Value(`"required"`), "x_profile": jsontext.Value(`{"v":1}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := serveMetadata(t, h, http.MethodGet)
	want := `{"resource":"https://api.example.com","authorization_servers":["https://as.example.com"],"scopes_supported":["epa.read","epa.write"],` +
		`"bearer_methods_supported":["header"],"x_profile":{"v":1},"zeta_asl_use":"required"}`
	if w.Code != http.StatusOK || w.Body.String() != want || w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("%d %s %s\nwant %s", w.Code, w.Header().Get("Content-Type"), w.Body, want)
	}
	w = serveMetadata(t, h, http.MethodHead)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != strconv.Itoa(len(want)) {
		t.Errorf("HEAD: %d, %d bytes, Content-Length %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}
}

// servers.md rule 28, method and path: the metadata takes GET and HEAD only; another method gets 405 with Allow.
func TestServerRule28_TheMetadataRefusesOtherMethodsWith405(t *testing.T) {
	h, err := NewProtectedResourceMetadataHandler(ProtectedResourceMetadata{Resource: "https://api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		w := serveMetadata(t, h, method)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" || w.Body.Len() != 0 {
			t.Errorf("%s: %d, Allow %q, %d bytes", method, w.Code, w.Header().Get("Allow"), w.Body.Len())
		}
	}
}

// RFC 9728 Section 2: an added member cannot replace a typed one, and its value is one JSON text; such a document,
// one without a resource or with malformed scopes, is refused.
func TestRFC9728_2_ACollidingOrMalformedMetadataMemberIsRefused(t *testing.T) {
	for name, extra := range map[string]map[string]jsontext.Value{
		"resource":                 {"resource": jsontext.Value(`"https://evil.example"`)},
		"authorization_servers":    {"authorization_servers": jsontext.Value(`["https://evil.example"]`)},
		"scopes_supported":         {"scopes_supported": jsontext.Value(`["x"]`)},
		"bearer_methods_supported": {"bearer_methods_supported": jsontext.Value(`["query"]`)},
		"jwks_uri":                 {"jwks_uri": jsontext.Value(`"https://evil.example/jwks"`)},
		"unquoted string":          {"zeta_asl_use": jsontext.Value(`required`)},
		"two texts":                {"zeta_asl_use": jsontext.Value(`"a" "b"`)},
		"duplicate name in value":  {"x": jsontext.Value(`{"a":1,"a":2}`)},
		"empty name":               {"": jsontext.Value(`1`)},
		"too large":                {"x": jsontext.Value(`"` + strings.Repeat("a", MaxMetadataMemberBytes) + `"`)},
	} {
		if _, err := NewProtectedResourceMetadataHandler(ProtectedResourceMetadata{Resource: "https://api.example.com", Extra: extra}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, doc := range map[string]ProtectedResourceMetadata{
		"no resource":      {},
		"scope with quote": {Resource: "https://api.example.com", ScopesSupported: []string{`a"b`}},
		"scope twice":      {Resource: "https://api.example.com", ScopesSupported: []string{"a", "a"}},
		"empty scope":      {Resource: "https://api.example.com", ScopesSupported: []string{""}},
	} {
		if _, err := NewProtectedResourceMetadataHandler(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// rotatingSource is a KeySource whose Refresh hands out next, or fails with err, and counts the calls.
type rotatingSource struct {
	current, next *jose.JSONWebKeySet
	err           error
	refreshes     int
}

func (s *rotatingSource) Keys() (*jose.JSONWebKeySet, error) { return s.current, nil }

func (s *rotatingSource) Refresh(context.Context) (*jose.JSONWebKeySet, error) {
	s.refreshes++
	if s.err != nil {
		return nil, s.err
	}
	s.current = s.next
	return s.current, nil
}

// RFC 7517 Section 4.5 and the authorization server's key rotation: a token naming a kid the set in force does not
// hold makes the PEP ask its key source once, and the rotated key verifies it; a known kid asks nothing, and a
// failed refresh refuses the token with the set in force kept.
func TestKeySource_AnUnknownKidRefreshesOnceAndVerifiesWithTheRotatedKey(t *testing.T) {
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldSet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: oldKey.Public(), KeyID: "old"}}}
	newSet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: oldKey.Public(), KeyID: "old"}, {Key: newKey.Public(), KeyID: "new"}}}
	payload := fmt.Sprintf(`{"aud":"https://rs.example","exp":%d}`, time.Now().Add(time.Hour).Unix())
	build := func(source KeySource) *PEP {
		p, err := NewBuilder().Resource("https://rs.example").WithKeySource(source).WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	source := &rotatingSource{current: oldSet, next: newSet}
	p := build(source)
	if _, err := p.VerifyAccessToken(signTyped(t, oldKey, "old", "at+jwt", payload)); err != nil || source.refreshes != 0 {
		t.Fatalf("known kid: %v, %d refreshes", err, source.refreshes)
	}
	if _, err := p.VerifyAccessToken(signTyped(t, newKey, "new", "at+jwt", payload)); err != nil || source.refreshes != 1 {
		t.Fatalf("rotated kid: %v, %d refreshes", err, source.refreshes)
	}

	failing := &rotatingSource{current: oldSet, err: errors.New("authorization server unreachable")}
	p = build(failing)
	if _, err := p.VerifyAccessToken(signTyped(t, newKey, "new", "at+jwt", payload)); err == nil || failing.refreshes != 1 {
		t.Fatalf("failed refresh: %v, %d refreshes", err, failing.refreshes)
	}
	if _, err := p.VerifyAccessToken(signTyped(t, oldKey, "old", "at+jwt", payload)); err != nil {
		t.Fatalf("the set in force was not kept: %v", err)
	}
	if failing.current != oldSet {
		t.Fatal("the set in force was replaced by a failed refresh")
	}
}
