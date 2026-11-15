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

package oidftest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

const (
	idpOrganization = "oidftest IDP"
	entityKID       = "idp-federation-sig"
	// requestURILifetime is how long a pushed request may be used (RFC 9126 section 2.2, expires_in).
	requestURILifetime = 90 * time.Second
	// codeLifetime is how long an authorization code may be redeemed; RFC 6749 section 4.1.2 recommends at most ten
	// minutes.
	codeLifetime = time.Minute
	// idTokenLifetime is exp − iat of an ID token.
	idTokenLifetime  = 5 * time.Minute
	requestURIPrefix = "urn:ietf:params:oauth:request_uri:"
)

// Defaults of what the IDP issues: gemSpec_IDP_Sek A_23129-06 Tabelle 7 has eGK and PIN at
// gematik-ehealth-loa-high, and A_27713-01 names the version in the JWE header.
const (
	DefaultACR     = "gematik-ehealth-loa-high"
	DefaultAMR     = "urn:telematik:auth:eGK"
	DefaultVersion = "1.0.0"
)

// User is the person who logs in at the IDP, by the claims of gemSpec_IDP_Sek A_22989-02 Tabelle 6. Subject is sub;
// left empty, a pairwise subject is derived from ID and the client_id (A_23197-01).
type User struct {
	ID           string
	DisplayName  string
	GivenName    string
	FamilyName   string
	Birthdate    string
	Profession   string
	Organization string
	Subject      string
}

// DefaultUser is the insured person the IDP authenticates until SetUser names another.
var DefaultUser = User{
	ID:           "X110411675",
	DisplayName:  "Erika Mustermann",
	GivenName:    "Erika",
	FamilyName:   "Mustermann",
	Birthdate:    "1964-08-12",
	Profession:   "1.2.276.0.76.4.49",
	Organization: "109500969",
}

// scopeClaims are the claims each scope of gemSpec_IDP_Sek Tabelle 6 puts into the ID token.
var scopeClaims = map[string][]string{
	"urn:telematik:geburtsdatum": {"birthdate"},
	"urn:telematik:display_name": {"urn:telematik:claims:display_name"},
	"urn:telematik:given_name":   {"urn:telematik:claims:given_name"},
	"urn:telematik:family_name":  {"urn:telematik:claims:family_name"},
	"urn:telematik:versicherter": {"urn:telematik:claims:profession", "urn:telematik:claims:id", "urn:telematik:claims:organization"},
}

// IDP is the federation's sektoral IDP. Its knobs are safe for concurrent use and hold for every login after them,
// except ExpireIDToken, which holds for the next token only.
type IDP struct {
	t   testing.TB
	fed *Federation
	// entity signs the IDP's entity statement and signed JWKS.
	entity crypto.Signer

	mu sync.Mutex
	// signing are the ID token keys, the current one last; all of them are published.
	signing    []signingKey
	user       User
	acr        string
	amr        []string
	version    string
	listed     bool
	expireNext bool
	notAnOP    bool
	lastError  string
	pushed     map[string]*pushedRequest
	codes      map[string]*grant
}

type signingKey struct {
	key crypto.Signer
	kid string
}

// pushedRequest is an authorization request the relying party pushed.
type pushedRequest struct {
	clientID, redirectURI, scope, state, nonce, challenge string
	expires                                               time.Time
}

// grant is an authorization code and the request it was issued for.
type grant struct {
	request  *pushedRequest
	authTime time.Time
	expires  time.Time
}

func newIDP(t testing.TB, fed *Federation) *IDP {
	return &IDP{
		t:       t,
		fed:     fed,
		entity:  newKey(t),
		signing: []signingKey{{key: newKey(t), kid: "idp-token-sig-1"}},
		user:    DefaultUser,
		acr:     DefaultACR,
		amr:     []string{DefaultAMR},
		version: DefaultVersion,
		listed:  true,
		pushed:  make(map[string]*pushedRequest),
		codes:   make(map[string]*grant),
	}
}

func (i *IDP) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /idp/.well-known/openid-federation", i.serveStatement)
	mux.HandleFunc("GET /idp/jwks", i.serveSignedJwks)
	mux.HandleFunc("POST /idp/par", i.servePAR)
	mux.HandleFunc("GET /idp/auth", i.serveAuthorization)
	mux.HandleFunc("POST /idp/token", i.serveToken)
}

// Issuer is the IDP's entity identifier and issuer.
func (i *IDP) Issuer() string {
	return i.fed.MasterURL() + "/idp"
}

// SetUser makes user the person who logs in.
func (i *IDP) SetUser(user User) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.user = user
}

// IssueACR makes the IDP issue acr as the ID token's acr, whatever was asked for.
func (i *IDP) IssueACR(acr string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.acr = acr
}

// IssueAMR makes the IDP issue amr as the ID token's amr.
func (i *IDP) IssueAMR(amr []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.amr = slices.Clone(amr)
}

// IssueVersion makes the IDP name version in the ID token's JWE header (gemSpec_IDP_Sek A_27713-01), "1.0.0" or
// "2.0.0"; its statement lists both.
func (i *IDP) IssueVersion(version string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.version = version
}

// RotateKey makes a new ID token key the current one: the next signed JWKS publishes it beside the earlier ones, and
// ID tokens are signed with it from now on. A relying party that kept the earlier JWKS has to refetch it
// (gemSpec_IDP_FD A_22861).
func (i *IDP) RotateKey() {
	key := newKey(i.t)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.signing = append(i.signing, signingKey{key: key, kid: fmt.Sprintf("idp-token-sig-%d", len(i.signing)+1)})
}

// Unlist takes the IDP off the master's IdP list.
func (i *IDP) Unlist() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.listed = false
}

// ExpireIDToken makes the next ID token one that has expired already.
func (i *IDP) ExpireIDToken() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.expireNext = true
}

// NotAnOP makes the IDP's entity statement one without openid_provider metadata.
func (i *IDP) NotAnOP() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.notAnOP = true
}

// LastError is the last refusal of the IDP, as "error: error_description" of its error response, or "" while it
// refused nothing.
func (i *IDP) LastError() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastError
}

func (i *IDP) isListed() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.listed
}

func (i *IDP) entityKeys() *jose.JSONWebKeySet {
	return publicKeySet(i.entity, entityKID)
}

// refuse answers with an error response and records it for LastError.
func (i *IDP) refuse(w http.ResponseWriter, status int, code, description string) {
	i.mu.Lock()
	i.lastError = code + ": " + description
	i.mu.Unlock()
	i.t.Logf("oidftest: the IDP refused: %s: %s", code, description)
	writeError(w, status, code, description)
}

// serveStatement answers with the IDP's entity statement (gemSpec_IDP_Sek Tabelle 3 and 4).
func (i *IDP) serveStatement(w http.ResponseWriter, _ *http.Request) {
	issuer := i.Issuer()
	i.mu.Lock()
	notAnOP := i.notAnOP
	i.mu.Unlock()
	metadata := map[string]any{"federation_entity": map[string]any{"name": idpOrganization}}
	if !notAnOP {
		claims := []string{}
		for _, names := range scopeClaims {
			claims = append(claims, names...)
		}
		slices.Sort(claims)
		scopes := []string{"openid"}
		for scope := range scopeClaims {
			scopes = append(scopes, scope)
		}
		slices.Sort(scopes)
		metadata["openid_provider"] = map[string]any{
			"issuer":                                   issuer,
			"signed_jwks_uri":                          issuer + "/jwks",
			"organization_name":                        idpOrganization,
			"logo_uri":                                 issuer + "/logo.png",
			"authorization_endpoint":                   issuer + "/auth",
			"pushed_authorization_request_endpoint":    issuer + "/par",
			"token_endpoint":                           issuer + "/token",
			"client_registration_types_supported":      []string{"automatic"},
			"subject_types_supported":                  []string{"pairwise"},
			"response_types_supported":                 []string{"code"},
			"response_modes_supported":                 []string{"query"},
			"grant_types_supported":                    []string{"authorization_code"},
			"scopes_supported":                         scopes,
			"claims_supported":                         claims,
			"require_pushed_authorization_requests":    true,
			"token_endpoint_auth_methods_supported":    []string{"self_signed_tls_client_auth"},
			"request_authentication_methods_supported": map[string]any{"ar": []string{"none"}, "par": []string{"self_signed_tls_client_auth"}},
			"id_token_signing_alg_values_supported":    []string{"ES256"},
			"id_token_encryption_alg_values_supported": []string{"ECDH-ES"},
			"id_token_encryption_enc_values_supported": []string{"A256GCM"},
			"user_type_supported":                      []string{"IP"},
			"ti_features_supported":                    map[string]any{"id_token_version_supported": []string{"1.0.0", "2.0.0"}},
		}
	}
	signed, err := i.fed.sign(i.entity, entityKID, "entity-statement+jwt", map[string]any{
		"iss":             issuer,
		"sub":             issuer,
		"jwks":            i.entityKeys(),
		"authority_hints": []string{i.fed.MasterURL()},
		"metadata":        metadata,
	})
	i.fed.serveDocument(w, "application/entity-statement+jwt", signed, err)
}

// serveSignedJwks answers with the ID token keys as a signed JWK Set (OpenID Federation 1.1 section 5.2.1, typ
// jwk-set+jwt), with exp.
func (i *IDP) serveSignedJwks(w http.ResponseWriter, _ *http.Request) {
	i.mu.Lock()
	keys := make([]jose.JSONWebKey, 0, len(i.signing))
	for _, signing := range i.signing {
		keys = append(keys, publicKeySet(signing.key, signing.kid).Keys[0])
	}
	i.mu.Unlock()
	signed, err := i.fed.sign(i.entity, entityKID, "jwk-set+jwt", map[string]any{
		"iss":  i.Issuer(),
		"keys": keys,
	})
	i.fed.serveDocument(w, "application/jwk-set+jwt", signed, err)
}

// form reads the request's form and refuses a parameter sent more than once (RFC 6749 section 3.1 and 3.2).
func form(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.New("the form does not parse")
	}
	for name, values := range r.Form {
		if len(values) != 1 {
			return nil, fmt.Errorf("%s is sent more than once", name)
		}
	}
	return r.Form, nil
}

// registration is what the IDP reads from a relying party's verified statement.
type registration struct {
	redirectURIs []string
	scope        []string
	encKey       jose.JSONWebKey
	certificate  []byte
}

// authenticate verifies the statement of the relying party clientID with the keys registered for it, and requires
// the request's client certificate to be the statement's x5c, byte for byte (self_signed_tls_client_auth, RFC 8705
// section 2.2). Its error is the error_description of an invalid_client response.
func (i *IDP) authenticate(r *http.Request, clientID string) (*registration, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate")
	}
	rp := i.fed.registered(clientID)
	if rp == nil {
		return nil, errors.New("client_id names no registered relying party")
	}
	signed, err := rp.statement()
	if err != nil {
		return nil, errors.New("the relying party's statement is not available")
	}
	payload, err := openid.VerifyJWS(bytes.TrimSpace(signed), rp.keys, openid.VerifyOptions{})
	if err != nil {
		return nil, errors.New("the relying party's statement does not verify with the registered keys")
	}
	if err := openid.ValidateLifetime(payload, i.fed.now(), 0); err != nil {
		return nil, errors.New("the relying party's statement is not valid now")
	}
	registered, err := readRegistration(payload, clientID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.TLS.PeerCertificates[0].Raw, registered.certificate) {
		return nil, errors.New("the client certificate is not the x5c of the relying party's statement")
	}
	return registered, nil
}

// relyingPartyStatement holds the members of a relying party's statement the IDP reads.
type relyingPartyStatement struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	Jwks     jsontext.Value `json:"jwks"`
	Metadata struct {
		RelyingParty *struct {
			RedirectURIs  []string       `json:"redirect_uris"`
			Scope         string         `json:"scope"`
			Jwks          jsontext.Value `json:"jwks"`
			SignedJwksURI string         `json:"signed_jwks_uri"`
		} `json:"openid_relying_party"`
	} `json:"metadata"`
}

func parseRelyingPartyStatement(payload []byte) (*relyingPartyStatement, error) {
	var statement relyingPartyStatement
	if err := openid.UnmarshalObject(payload, openid.PayloadDepth, openid.PayloadMembers, &statement); err != nil {
		return nil, fmt.Errorf("the statement does not parse: %w", err)
	}
	return &statement, nil
}

// readRegistration reads redirect_uris, scope and the keys of the openid_relying_party metadata: the enc key the ID
// token is encrypted to (A_23194) and the client certificate (x5c of a sig key, A_23183).
func readRegistration(payload []byte, clientID string) (*registration, error) {
	statement, err := parseRelyingPartyStatement(payload)
	if err != nil {
		return nil, err
	}
	if statement.Issuer != clientID || statement.Subject != clientID {
		return nil, errors.New("the relying party's statement names another iss or sub")
	}
	metadata := statement.Metadata.RelyingParty
	if metadata == nil {
		return nil, errors.New("the relying party's statement has no openid_relying_party metadata")
	}
	if len(metadata.Jwks) == 0 {
		return nil, errors.New("oidftest reads the relying party's keys from jwks only, not from signed_jwks_uri")
	}
	keys, err := openid.ParseKeySet(metadata.Jwks)
	if err != nil {
		return nil, errors.New("the relying party's jwks does not parse")
	}
	registered := &registration{redirectURIs: metadata.RedirectURIs, scope: strings.Fields(metadata.Scope)}
	var foundEnc bool
	for _, key := range keys.Keys {
		switch {
		case key.Use == "enc" && !foundEnc:
			registered.encKey, foundEnc = key, true
		case key.Use == "sig" && len(key.Certificates) > 0 && registered.certificate == nil:
			registered.certificate = key.Certificates[0].Raw
		}
	}
	if !foundEnc || registered.certificate == nil {
		return nil, errors.New("the relying party's jwks lacks an enc key or a sig key with x5c")
	}
	return registered, nil
}

// servePAR takes a pushed authorization request (RFC 9126 section 2) and answers 201 with a request_uri for
// requestURILifetime.
func (i *IDP) servePAR(w http.ResponseWriter, r *http.Request) {
	values, err := form(r)
	if err != nil {
		i.refuse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	clientID := values.Get("client_id")
	registered, err := i.authenticate(r, clientID)
	if err != nil {
		i.refuse(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	for _, name := range []string{"redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		if values.Get(name) == "" {
			i.refuse(w, http.StatusBadRequest, "invalid_request", name+" is missing")
			return
		}
	}
	if values.Has("request_uri") || values.Has("request") {
		i.refuse(w, http.StatusBadRequest, "invalid_request", "a pushed request carries no request_uri or request")
		return
	}
	if values.Get("response_type") != "code" {
		i.refuse(w, http.StatusBadRequest, "unsupported_response_type", "response_type has to be code")
		return
	}
	redirectURI := values.Get("redirect_uri")
	if !slices.Contains(registered.redirectURIs, redirectURI) {
		i.refuse(w, http.StatusBadRequest, "invalid_request", "redirect_uri is none the relying party registered")
		return
	}
	scopes := strings.Split(values.Get("scope"), " ")
	if !slices.Contains(scopes, "openid") {
		i.refuse(w, http.StatusBadRequest, "invalid_scope", "scope lacks openid")
		return
	}
	for _, scope := range scopes {
		if !slices.Contains(registered.scope, scope) {
			i.refuse(w, http.StatusBadRequest, "invalid_scope", "scope holds one the relying party did not register")
			return
		}
	}
	if values.Get("code_challenge_method") != openid.CodeChallengeMethodS256 {
		i.refuse(w, http.StatusBadRequest, "invalid_request", "code_challenge_method has to be S256")
		return
	}
	// RFC 7636 section 4.2: BASE64URL(SHA256(verifier)) is 43 characters.
	if challenge, err := base64.RawURLEncoding.DecodeString(values.Get("code_challenge")); err != nil || len(challenge) != sha256.Size {
		i.refuse(w, http.StatusBadRequest, "invalid_request", "code_challenge is no S256 challenge")
		return
	}

	requestURI := requestURIPrefix + random()
	i.mu.Lock()
	i.pushed[requestURI] = &pushedRequest{
		clientID:    clientID,
		redirectURI: redirectURI,
		scope:       values.Get("scope"),
		state:       values.Get("state"),
		nonce:       values.Get("nonce"),
		challenge:   values.Get("code_challenge"),
		expires:     i.fed.now().Add(requestURILifetime),
	}
	i.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.MarshalWrite(w, map[string]any{"request_uri": requestURI, "expires_in": int(requestURILifetime.Seconds())})
}

// serveAuthorization takes the request_uri of a pushed request once, authenticates the user at once and redirects to
// the request's redirect_uri with code and state (RFC 6749 section 4.1.2). A request it cannot take is answered to
// the user agent, not redirected (section 4.1.2.1).
func (i *IDP) serveAuthorization(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query["client_id"]) != 1 || len(query["request_uri"]) != 1 {
		i.refuse(w, http.StatusBadRequest, "invalid_request", "client_id and request_uri are required once each")
		return
	}
	now := i.fed.now()
	i.mu.Lock()
	request, found := i.pushed[query.Get("request_uri")]
	delete(i.pushed, query.Get("request_uri"))
	i.mu.Unlock()
	switch {
	case !found:
		i.refuse(w, http.StatusBadRequest, "invalid_request", "request_uri is unknown or used")
		return
	case now.After(request.expires):
		i.refuse(w, http.StatusBadRequest, "invalid_request", "request_uri has expired")
		return
	case query.Get("client_id") != request.clientID:
		i.refuse(w, http.StatusBadRequest, "invalid_request", "client_id is not the one that pushed the request")
		return
	}
	code := random()
	i.mu.Lock()
	i.codes[code] = &grant{request: request, authTime: now, expires: now.Add(codeLifetime)}
	i.mu.Unlock()
	callback := url.Values{}
	callback.Set("code", code)
	callback.Set("state", request.state)
	w.Header().Set("Location", request.redirectURI+"?"+callback.Encode())
	w.WriteHeader(http.StatusFound)
}

// serveToken redeems a code once (RFC 6749 section 4.1.3) for the client it was issued to, after mutual TLS, the
// redirect_uri of its request and the code_verifier of its challenge (RFC 7636 section 4.6), and answers with the
// encrypted ID token.
func (i *IDP) serveToken(w http.ResponseWriter, r *http.Request) {
	values, err := form(r)
	if err != nil {
		i.refuse(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	clientID := values.Get("client_id")
	registered, err := i.authenticate(r, clientID)
	if err != nil {
		i.refuse(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if values.Get("grant_type") != "authorization_code" {
		i.refuse(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type has to be authorization_code")
		return
	}
	now := i.fed.now()
	i.mu.Lock()
	issued, found := i.codes[values.Get("code")]
	delete(i.codes, values.Get("code"))
	i.mu.Unlock()
	switch {
	case !found:
		i.refuse(w, http.StatusBadRequest, "invalid_grant", "code is unknown or used")
		return
	case now.After(issued.expires):
		i.refuse(w, http.StatusBadRequest, "invalid_grant", "code has expired")
		return
	case issued.request.clientID != clientID:
		i.refuse(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client")
		return
	case values.Get("redirect_uri") != issued.request.redirectURI:
		i.refuse(w, http.StatusBadRequest, "invalid_grant", "redirect_uri is not the one of the authorization request")
		return
	case subtle.ConstantTimeCompare([]byte(openid.S256Challenge(values.Get("code_verifier"))), []byte(issued.request.challenge)) != 1:
		i.refuse(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
		return
	}
	idToken, err := i.idToken(issued, registered, now)
	if err != nil {
		i.t.Errorf("oidftest: issuing the ID token: %v", err)
		http.Error(w, "issuing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.MarshalWrite(w, map[string]any{
		"access_token": random(),
		"token_type":   "Bearer",
		"expires_in":   int(idTokenLifetime.Seconds()),
		"scope":        issued.request.scope,
		"id_token":     idToken,
	})
}

// idToken signs the ID token with the current key (ES256, with kid) and encrypts it with ECDH-ES and A256GCM to the
// relying party's enc key, under that key's kid and with the version in the protected header (gemSpec_IDP_FD
// A_23194, A_23195; gemSpec_IDP_Sek A_27713-01).
func (i *IDP) idToken(issued *grant, registered *registration, now time.Time) (string, error) {
	i.mu.Lock()
	user, acr, amr, version := i.user, i.acr, slices.Clone(i.amr), i.version
	signing := i.signing[len(i.signing)-1]
	expired := i.expireNext
	i.expireNext = false
	i.mu.Unlock()

	request := issued.request
	issuedAt, authTime := now, issued.authTime
	if expired {
		issuedAt = now.Add(-2 * idTokenLifetime)
		authTime = issuedAt
	}
	subject := user.Subject
	if subject == "" {
		sum := sha256.Sum256([]byte(request.clientID + " " + user.ID))
		subject = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	claims := map[string]any{
		"iss":       i.Issuer(),
		"sub":       subject,
		"aud":       request.clientID,
		"nonce":     request.nonce,
		"iat":       issuedAt.Unix(),
		"exp":       issuedAt.Add(idTokenLifetime).Unix(),
		"auth_time": authTime.Unix(),
		"acr":       acr,
		"amr":       amr,
	}
	values := map[string]string{
		"birthdate":                         user.Birthdate,
		"urn:telematik:claims:display_name": user.DisplayName,
		"urn:telematik:claims:given_name":   user.GivenName,
		"urn:telematik:claims:family_name":  user.FamilyName,
		"urn:telematik:claims:profession":   user.Profession,
		"urn:telematik:claims:id":           user.ID,
		"urn:telematik:claims:organization": user.Organization,
	}
	for scope := range strings.SplitSeq(request.scope, " ") {
		for _, name := range scopeClaims[scope] {
			if values[name] != "" {
				claims[name] = values[name]
			}
		}
	}
	signed, err := signJWS(signing.key, signing.kid, "JWT", claims)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: registered.encKey.Key, KeyID: registered.encKey.KeyID},
		(&jose.EncrypterOptions{}).WithContentType("JWT").WithHeader("version", version))
	if err != nil {
		return "", err
	}
	encrypted, err := encrypter.Encrypt(signed)
	if err != nil {
		return "", err
	}
	return encrypted.CompactSerialize()
}

// random is a value of 128 random bits, for request_uri, code and access token.
func random() string {
	return rand.Text()
}
