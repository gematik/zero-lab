//go:build mockidp

// Package mockidp is a co-hosted, non-production OpenID Provider for the PDP. It lets login run the REAL
// op-callback path — browser → mock /auth login page → PDP /op-callback?code → code exchange → signed
// id_token validation — with no external IdP and no special-casing in the authorization-server flow: the
// mock registers as an ordinary oidc.Client provider. It is compiled ONLY with `-tags mockidp`; production
// builds exclude it (and its routes) entirely.
package mockidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
	"golang.org/x/oauth2"
)

const (
	pathPrefix   = "/mock-idp"
	mockClientID = "pdp-mock-client"
)

// Host is what the mock OP needs from the PDP authorization server, expressed as an interface so this package
// never imports authzserver (which would be an import cycle, since the build-tagged seam there imports this).
type Host interface {
	IssuerBaseURL() string   // the PDP's public base URL (its issuer)
	OPCallbackURL() string   // the PDP's op-callback URL (where the OP redirects back with the code)
	AddProvider(oidc.Client) // register the mock as a normal upstream provider in the AS registry
}

// Identity is the canned login the mock returns in its id_token.
type Identity struct {
	Subject string
	Claims  map[string]any
}

type pendingAuth struct {
	clientID      string
	nonce         string
	codeChallenge string
}

type provider struct {
	issuer  string
	id      Identity
	signKey jwk.Key
	jwks    jwk.Set

	mu    sync.Mutex
	codes map[string]pendingAuth // single-use OP authorization codes (in-memory; dev/non-prod only)
}

// Register builds the mock OP, mounts its routes on mux, and registers it as a normal oidc provider so the
// generic startOpenidProviderLogin / OPCallbackEndpoint / OpenidProviders paths handle it unchanged.
func Register(h Host, mux *http.ServeMux, id Identity) error {
	key, err := newSigningKey()
	if err != nil {
		return fmt.Errorf("mockidp signing key: %w", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return fmt.Errorf("mockidp public key: %w", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		return err
	}
	p := &provider{
		issuer:  strings.TrimRight(h.IssuerBaseURL(), "/") + pathPrefix,
		id:      id,
		signKey: key,
		jwks:    set,
		codes:   map[string]pendingAuth{},
	}
	mux.HandleFunc("GET "+pathPrefix+"/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET "+pathPrefix+"/auth", p.handleAuthPage)
	mux.HandleFunc("POST "+pathPrefix+"/auth", p.handleAuthSubmit)
	mux.HandleFunc("POST "+pathPrefix+"/token", p.handleToken)
	mux.HandleFunc("GET "+pathPrefix+"/jwks", p.handleJWKS)

	h.AddProvider(&mockClient{issuer: p.issuer, clientID: mockClientID, redirectURI: h.OPCallbackURL(), pub: pub})
	return nil
}

func newSigningKey() (jwk.Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := jwk.Import(priv)
	if err != nil {
		return nil, err
	}
	_ = key.Set(jwk.KeyIDKey, ksuid.New().String())
	_ = key.Set(jwk.AlgorithmKey, jwa.ES256())
	return key, nil
}

func (p *provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/auth",
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

func (p *provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, p.jwks)
}

// loginPage uses the gematik developer style (light, Inter, gematik palette) so the mock matches pep's auth
// UI and the metsubushi app. No web-font fetch (airgapped): Inter if present, else system fonts.
var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mock IdP</title><style>
:root{--white:#fff;--almost-black:#252834;--dark-grey:#59677c;--light-grey:#e8edf3;--dark-blue:#000e52;--magenta:#ff1b7c}
*{box-sizing:border-box}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:17px;color:var(--almost-black);
margin:0;min-height:100vh;display:grid;place-items:center;padding:1.5rem;-webkit-font-smoothing:antialiased;
background:radial-gradient(120% 120% at 100% 0%,rgba(0,183,255,.10),transparent 55%),
radial-gradient(90% 90% at 0% 0%,rgba(0,255,100,.12),transparent 45%),var(--white)}
main{background:var(--white);border:1px solid var(--light-grey);border-radius:24px;padding:2.25rem;
width:min(92%,22rem);box-shadow:0 4px 16px 0 rgb(0 14 82 / 12%)}
h1{font-size:1.3rem;font-weight:800;letter-spacing:-.01em;color:var(--dark-blue);margin:0 0 .25rem}
h1 small{color:var(--dark-grey);font-weight:600;font-size:.7em}
p{color:var(--dark-grey);margin:.2rem 0 0}
button{font-family:inherit;font-size:1rem;font-weight:700;width:100%;margin-top:1.4rem;color:var(--white);
background:var(--dark-blue);border:2px solid var(--dark-blue);border-radius:8px;padding:.7rem 1.2rem;cursor:pointer;
transition:background .25s ease,border-color .25s ease}
button:hover{background:var(--magenta);border-color:var(--magenta)}
</style></head>
<body><main><h1>Mock IdP <small>(non-prod)</small></h1>
<p>Sign in as <strong>{{.Subject}}</strong></p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<button type="submit">Sign in</button>
</form></main></body></html>`))

func (p *provider) handleAuthPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginPage.Execute(w, map[string]string{
		"Subject":       p.id.Subject,
		"Action":        pathPrefix + "/auth",
		"ClientID":      q.Get("client_id"),
		"RedirectURI":   q.Get("redirect_uri"),
		"State":         q.Get("state"),
		"Nonce":         q.Get("nonce"),
		"CodeChallenge": q.Get("code_challenge"),
	})
}

func (p *provider) handleAuthSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	code := ksuid.New().String()
	p.mu.Lock()
	p.codes[code] = pendingAuth{
		clientID:      r.FormValue("client_id"),
		nonce:         r.FormValue("nonce"),
		codeChallenge: r.FormValue("code_challenge"),
	}
	p.mu.Unlock()

	q := url.Values{}
	q.Set("code", code)
	q.Set("state", r.FormValue("state"))
	http.Redirect(w, r, redirectURI+"?"+q.Encode(), http.StatusFound)
}

func (p *provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "bad form")
		return
	}
	code := r.FormValue("code")
	p.mu.Lock()
	pend, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !ok {
		oauthError(w, "invalid_grant", "unknown or used code")
		return
	}
	if pend.codeChallenge != "" {
		if oauth2.S256ChallengeFromVerifier(r.FormValue("code_verifier")) != pend.codeChallenge {
			oauthError(w, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	now := time.Now()
	tok := jwt.New()
	tok.Set("iss", p.issuer)
	tok.Set("sub", p.id.Subject)
	tok.Set("aud", pend.clientID)
	tok.Set("nonce", pend.nonce)
	tok.Set("iat", now.Unix())
	tok.Set("exp", now.Add(5*time.Minute).Unix())
	for k, v := range p.id.Claims {
		tok.Set(k, v)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), p.signKey))
	if err != nil {
		oauthError(w, "server_error", "sign id_token: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "mock-" + code,
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     string(signed),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}
