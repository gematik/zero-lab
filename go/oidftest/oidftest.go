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

// Package oidftest is a gematik OpenID Federation for tests: a federation master and one sektoral IDP on one
// httptest TLS server, so that a relying party built on package oidf logs in end to end without the network. It is
// for tests only; not for production builds (`just mod-check` refuses a non-test package that imports it).
//
// The master is at the server's root, the IDP at "/idp" below it:
//
//	/.well-known/openid-federation       the master's entity statement
//	/fetch?iss=…&sub=…                   the master's statement about the IDP or a registered relying party
//	/idp-list                            the IdP list (gemSpec_IDP_FedMaster Tabelle 8)
//	/idp/.well-known/openid-federation   the IDP's entity statement
//	/idp/jwks                            the IDP's signed JWKS, the keys its ID tokens are signed with
//	/idp/par                             pushed authorization requests (RFC 9126), mutual TLS
//	/idp/auth                            the authorization endpoint, which answers at once with a code
//	/idp/token                           the token endpoint, mutual TLS
//
// The master onboards a relying party with [Federation.RegisterRelyingParty]. The IDP holds every login to what the
// relying party's signed statement registers, as a sektoral IDP does: the client certificate is the statement's x5c
// (self_signed_tls_client_auth, RFC 8705 section 2.2), the redirect_uri one the statement names, the scopes within its
// scope, PKCE with S256, and request_uri and code are used once. What it refused last, and why, is
// [IDP.LastError]. Its ID token is signed with ES256 and encrypted with ECDH-ES and A256GCM to the relying party's
// enc key (gemSpec_IDP_FD A_23194, A_23195). The knobs of [IDP] make it issue what a relying party has to refuse.
//
// Every key is generated in memory per Federation and never leaves it (keys.md rule 1).
package oidftest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"

	"github.com/gematik/zero-lab/go/openid"
)

const (
	// documentLifetime is exp − iat of every document the master and the IDP sign.
	documentLifetime = time.Hour
	masterKID        = "fedmaster-sig"
)

// Federation is a federation master and one sektoral IDP on one httptest TLS server. It is safe for concurrent use.
type Federation struct {
	t      testing.TB
	server *httptest.Server
	clock  func() time.Time
	master crypto.Signer
	idp    *IDP

	mu             sync.Mutex
	requests       map[string]int
	relyingParties map[string]*relyingParty
}

// relyingParty is a relying party the master onboarded: the federation keys its statement named then, and where its
// current statement comes from.
type relyingParty struct {
	keys      *jose.JSONWebKeySet
	statement func() ([]byte, error)
}

// Option configures a Federation.
type Option func(*options)

type options struct {
	clock func() time.Time
}

// WithClock sets the time documents and ID tokens are issued at, and request_uri and code expire by; the default is
// the system clock. A relying party judged at a fake clock needs the same one here.
func WithClock(now func() time.Time) Option {
	return func(o *options) {
		o.clock = now
	}
}

// New starts the federation on a TLS server that asks for, but does not require, a client certificate: the master
// ignores it, the IDP's PAR and token endpoints require it. The server is closed when the test ends.
func New(t testing.TB, opts ...Option) *Federation {
	t.Helper()
	o := &options{clock: time.Now}
	for _, opt := range opts {
		opt(o)
	}
	f := &Federation{
		t:              t,
		clock:          o.clock,
		master:         newKey(t),
		requests:       make(map[string]int),
		relyingParties: make(map[string]*relyingParty),
	}
	f.idp = newIDP(t, f)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-federation", f.serveMasterStatement)
	mux.HandleFunc("GET /fetch", f.serveFetch)
	mux.HandleFunc("GET /idp-list", f.serveIdpList)
	f.idp.routes(mux)

	f.server = httptest.NewUnstartedServer(f.counted(mux))
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

// newKey generates a P-256 key that stays in memory and signs through crypto.Signer.
func newKey(t testing.TB) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// counted counts the requests by path, for Requests.
func (f *Federation) counted(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests[r.URL.Path]++
		f.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// MasterURL is the master's entity identifier, the server's URL.
func (f *Federation) MasterURL() string {
	return f.server.URL
}

// TrustAnchor is the master's public signing key, with kid, use and alg, as a relying party configures it.
func (f *Federation) TrustAnchor() *jose.JSONWebKeySet {
	return publicKeySet(f.master, masterKID)
}

// Client trusts the server's certificate and presents none. A relying party takes it as its base client and layers
// its client certificate onto a copy for PAR and token requests.
func (f *Federation) Client() *http.Client {
	return f.server.Client()
}

// IDP is the federation's sektoral IDP.
func (f *Federation) IDP() *IDP {
	return f.idp
}

// Requests counts the requests that reached path, one of the paths of the package documentation; a query is not part
// of it.
func (f *Federation) Requests(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[path]
}

// RegisterRelyingParty onboards the relying party entityID, as the master's registration does. The master takes the
// federation keys from the statement statement returns now, which has to be self-signed with one of them and name
// entityID as iss and sub: trust on onboarding. Later the IDP calls statement whenever it needs the relying party's
// statement, verifies it with the keys taken now, and reads its keys and metadata from it. The master does not
// fetch anything over the network. It fails the test if the statement does not verify.
func (f *Federation) RegisterRelyingParty(entityID string, statement func() ([]byte, error)) {
	f.t.Helper()
	signed, err := statement()
	if err != nil {
		f.t.Fatalf("oidftest: the statement of %s: %v", entityID, err)
	}
	keys, err := selfSignedKeys(signed)
	if err != nil {
		f.t.Fatalf("oidftest: the statement of %s: %v", entityID, err)
	}
	payload, err := openid.VerifyJWS(signed, keys, openid.VerifyOptions{})
	if err != nil {
		f.t.Fatalf("oidftest: the statement of %s is not self-signed: %v", entityID, err)
	}
	parsed, err := parseRelyingPartyStatement(payload)
	if err != nil {
		f.t.Fatalf("oidftest: the statement of %s: %v", entityID, err)
	}
	if parsed.Issuer != entityID || parsed.Subject != entityID {
		f.t.Fatalf("oidftest: the statement of %s names another iss or sub", entityID)
	}
	f.mu.Lock()
	f.relyingParties[entityID] = &relyingParty{keys: keys, statement: statement}
	f.mu.Unlock()
}

// registered is the relying party onboarded as entityID, or nil.
func (f *Federation) registered(entityID string) *relyingParty {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.relyingParties[entityID]
}

// selfSignedKeys reads the top-level jwks of a statement whose signature is not verified yet.
func selfSignedKeys(signed []byte) (*jose.JSONWebKeySet, error) {
	parts := strings.Split(string(signed), ".")
	if len(parts) != 3 {
		return nil, errors.New("no compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("the payload is no base64url")
	}
	statement, err := parseRelyingPartyStatement(payload)
	if err != nil {
		return nil, err
	}
	if len(statement.Jwks) == 0 {
		return nil, errors.New("no jwks")
	}
	return openid.ParseKeySet(statement.Jwks)
}

// Authorize is the user agent at the authorization endpoint: it requests authenticationURL, the URL a relying party's
// AuthenticationURL returned, without following the redirect, and returns where the IDP redirects to, the relying
// party's redirect_uri with code and state.
func (f *Federation) Authorize(ctx context.Context, authenticationURL string) (*url.URL, error) {
	client := *f.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, authenticationURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("authorization endpoint: status %d: %s", response.StatusCode, body)
	}
	return url.Parse(response.Header.Get("Location"))
}

func (f *Federation) now() time.Time {
	return f.clock()
}

// sign signs claims as a compact JWS of typ with key under kid, and gives them iat and exp first.
func (f *Federation) sign(key crypto.Signer, kid, typ string, claims map[string]any) ([]byte, error) {
	now := f.now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(documentLifetime).Unix()
	return signJWS(key, kid, typ, claims)
}

func signJWS(key crypto.Signer, kid, typ string, claims map[string]any) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key)},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid),
	)
	if err != nil {
		return nil, err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return []byte(compact), nil
}

func publicKeySet(key crypto.Signer, kid string) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: kid, Use: "sig", Algorithm: string(jose.ES256)}}}
}

// serveDocument answers with a signed document, or fails the request when signing failed.
func (f *Federation) serveDocument(w http.ResponseWriter, contentType string, signed []byte, err error) {
	if err != nil {
		f.t.Errorf("oidftest: signing a document: %v", err)
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(signed)
}

func (f *Federation) serveMasterStatement(w http.ResponseWriter, _ *http.Request) {
	master := f.MasterURL()
	signed, err := f.sign(f.master, masterKID, "entity-statement+jwt", map[string]any{
		"iss":  master,
		"sub":  master,
		"jwks": publicKeySet(f.master, masterKID),
		"metadata": map[string]any{"federation_entity": map[string]any{
			"name":                      "oidftest federation master",
			"federation_fetch_endpoint": master + "/fetch",
			"idp_list_endpoint":         master + "/idp-list",
		}},
	})
	f.serveDocument(w, "application/entity-statement+jwt", signed, err)
}

// serveFetch answers with the master's statement about the IDP or a registered relying party (OpenID Federation 1.0
// section 8.1.1), vouching for the keys their own statements are signed with.
func (f *Federation) serveFetch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query["iss"]) != 1 || len(query["sub"]) != 1 || query.Get("iss") != f.MasterURL() {
		writeError(w, http.StatusBadRequest, "invalid_request", "iss has to name this master and sub one entity")
		return
	}
	subject := query.Get("sub")
	var keys *jose.JSONWebKeySet
	switch rp := f.registered(subject); {
	case subject == f.idp.Issuer():
		keys = f.idp.entityKeys()
	case rp != nil:
		keys = rp.keys
	default:
		writeError(w, http.StatusNotFound, "not_found", "no such subordinate")
		return
	}
	signed, err := f.sign(f.master, masterKID, "entity-statement+jwt", map[string]any{
		"iss":  f.MasterURL(),
		"sub":  subject,
		"jwks": keys,
	})
	f.serveDocument(w, "application/entity-statement+jwt", signed, err)
}

// serveIdpList answers with the IdP list of gemSpec_IDP_FedMaster Tabelle 8 and Tabelle 9 (typ idp-list+jwt).
func (f *Federation) serveIdpList(w http.ResponseWriter, _ *http.Request) {
	entries := []map[string]any{}
	if f.idp.isListed() {
		entries = append(entries, map[string]any{
			"iss":                 f.idp.Issuer(),
			"organization_name":   idpOrganization,
			"logo_uri":            f.idp.Issuer() + "/logo.png",
			"user_type_supported": []string{"IP"},
			"pkv":                 false,
		})
	}
	signed, err := f.sign(f.master, masterKID, "idp-list+jwt", map[string]any{
		"iss":        f.MasterURL(),
		"idp_entity": entries,
	})
	f.serveDocument(w, "application/jwt", signed, err)
}

// writeError answers with an error response of RFC 6749 section 5.2.
func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error": code, "error_description": description})
}
