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

package pep_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

func TestEnforcersJSON(t *testing.T) {
	js := []byte(`{
		"type": "AllOf",
		"enforcers": [
			{
				"type": "Scope",
				"scope": "read"
			},
			{
				"type": "Deny"
			}
		]
	}`)

	eh := new(pep.EnforcerHolder)
	if err := json.Unmarshal(js, eh); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %s", err)
	}

	ao, ok := eh.Enforcer.(*pep.EnforcerAllOf)
	if !ok {
		t.Fatalf("Expected EnforcerAllOf, got %T", eh.Enforcer)
	}

	t.Logf("EnforcerAllOf: %v", ao)

	next := func(_ pep.Context) {
		t.Fatal("next handler should not be called")
	}

	denyCalled := false
	deny := func(_ pep.Context, err pep.Error) {
		t.Logf("Denying request: %v", err)
		denyCalled = true
	}

	pep := createPEP(t)

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	ctx := pep.NewContext(resp, req).WithDeny(deny)

	ao.Apply(ctx, next)

	if !denyCalled {
		t.Fatal("Deny function should have been called")
	}

	asJSON, err := json.Marshal(eh)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}
	t.Logf("Marshalled JSON: %s", asJSON)
}

func TestEnforcersLogic(t *testing.T) {
	p := createPEP(t)

	denyAllEnforcer := pep.EnforcerAllOf{
		TypeVal: pep.EnforcerTypeAllOf,
		EnforcerHolders: []pep.EnforcerHolder{
			{&pep.EnforcerDeny{TypeVal: pep.EnforcerTypeDeny}},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /public", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("public"))
	})

	mux.HandleFunc("GET /private",
		p.GuardedHandlerFunc(denyAllEnforcer, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("private"))
		}),
	)

	customEnforcer := pep.EnforcerFromFunc(func(ctx pep.Context, next pep.HandlerFunc) {
		if ctx.Request().Header.Get("X-Api-Key") != "api-key" {
			ctx.Deny(pep.ErrorAccessDeinied("API key does not match"))
			return
		}
		ctx.Slogger().Info("API key matched")
		next(ctx)
	})

	mux.HandleFunc("GET /api-key", p.GuardedHandlerFunc(customEnforcer, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("protected-by-api-key"))
	}))

	anyOfEnforcer := pep.EnforcerAnyOf{
		TypeVal: pep.EnforcerTypeAnyOf,
		EnforcerHolders: []pep.EnforcerHolder{
			{&pep.EnforcerDeny{TypeVal: pep.EnforcerTypeDeny}},
			{customEnforcer},
		},
	}

	mux.HandleFunc("GET /any-of", p.GuardedHandlerFunc(anyOfEnforcer, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("any-of"))
	}))

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()

	tests := []struct {
		url            string
		expectedStatus int
		expectedBody   string
		createRequest  func() (*http.Request, error)
	}{
		{url: "/public", expectedStatus: http.StatusOK, expectedBody: "public"},
		{url: "/private", expectedStatus: http.StatusForbidden, expectedBody: "{\"error\":\"access_denied\",\"error_description\":\"Access denied by configuration\"}\n"},
		{url: "/api-key", expectedStatus: http.StatusOK, expectedBody: "protected-by-api-key", createRequest: func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodGet, server.URL+"/api-key", nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("X-Api-Key", "api-key")
			return req, nil
		}},
		{url: "/api-key", expectedStatus: http.StatusForbidden, expectedBody: "{\"error\":\"access_denied\",\"error_description\":\"API key does not match\"}\n"},
		{url: "/any-of", expectedStatus: http.StatusForbidden, expectedBody: "{\"error\":\"access_denied\",\"error_description\":\"None of the enforcers in any_of allowed the request\"}\n"},
		{url: "/any-of", expectedStatus: http.StatusOK, expectedBody: "any-of", createRequest: func() (*http.Request, error) {
			req, err := http.NewRequest(http.MethodGet, server.URL+"/any-of", nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("X-Api-Key", "api-key")
			return req, nil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL+tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tt.createRequest != nil {
				req, err = tt.createRequest()
				if err != nil {
					t.Fatal(err)
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, string(body))
			}
		})
	}
}

func TestEnforcerScope(t *testing.T) {
	p := createPEP(t)
	enforcerRead := new(pep.EnforcerHolder)
	if err := json.Unmarshal([]byte(`{"type":"AllOf","enforcers":[{"type":"AuthorizationBearer"},{"type":"Scope","scope":"read"}]}`), enforcerRead); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %s", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/public", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("public"))
	})

	mux.HandleFunc("/read",
		p.GuardedHandlerFunc(enforcerRead, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("read"))
		}),
	)

	enforcerWrite := new(pep.EnforcerHolder)
	if err := json.Unmarshal([]byte(`{"type":"AllOf","enforcers":[{"type":"AuthorizationBearer"},{"type":"Scope","scope":"write"}]}`), enforcerWrite); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %s", err)
	}

	mux.HandleFunc("/write",
		p.GuardedHandlerFunc(enforcerWrite, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("write"))
		}),
	)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()

	tests := []struct {
		url            string
		expectedStatus int
		expectedBody   string
		request        *http.Request
	}{
		{url: "/public", expectedStatus: http.StatusOK, expectedBody: "public"},
		{url: "/read", expectedStatus: http.StatusUnauthorized},
		{url: "/write", expectedStatus: http.StatusUnauthorized},
		{url: "/write", expectedStatus: http.StatusOK, expectedBody: "write", request: createRequestWithAccessToken(t, server.URL+"/write", []byte(privateJWK1), []string{"write"}, time.Now().Add(time.Hour))},
		{url: "/read", expectedStatus: http.StatusOK, expectedBody: "read", request: createRequestWithAccessToken(t, server.URL+"/read", []byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour))},
		{url: "/read", expectedStatus: http.StatusUnauthorized, request: createRequestWithAccessToken(t, server.URL+"/read", []byte(privateJWKUnknown), []string{"read"}, time.Now().Add(time.Hour))},
		{url: "/read", expectedStatus: http.StatusUnauthorized, request: createRequestWithAccessToken(t, server.URL+"/read", []byte(privateJWK1), []string{"read"}, time.Now().Add(-2*time.Hour))},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req := tt.request
			if req == nil {
				var err error
				req, err = http.NewRequest(http.MethodGet, server.URL+tt.url, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			if tt.expectedBody == "" {
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, string(body))
			}
		})
	}
}

func createTestAccessToken(keyBytes []byte, scopes []string, exp time.Time, jkt string) (string, error) {
	scope := strings.Join(scopes, " ")
	prk := jose.JSONWebKey{}
	if err := json.Unmarshal(keyBytes, &prk); err != nil {
		return "", err
	}
	claims := map[string]any{
		"scope": scope,
		"aud":   []string{"https://example.com"},
		"exp":   exp.Unix(),
	}
	if jkt != "" {
		claims["cnf"] = map[string]string{"jkt": jkt}
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: prk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	signed, err := object.CompactSerialize()
	if err != nil {
		return "", err
	}

	slog.Info("signed access token", "token", string(signed))

	return string(signed), nil
}

func createRequestWithAccessToken(t *testing.T, url string, keyBytes []byte, scopes []string, exp time.Time) *http.Request {
	accessToken, err := createTestAccessToken(keyBytes, scopes, exp, "")
	if err != nil {
		t.Fatal(err)
		return nil
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	return req
}

func createRequestWithAccessTokenAndDPoP(t *testing.T, url string, keyBytes []byte, scopes []string, exp time.Time) *http.Request {
	proofKey, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := createTestAccessToken(keyBytes, scopes, exp, proofKey.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := proofKey.Sign(req, dpop.ProofOptions{AccessToken: accessToken}); err != nil {
		t.Fatal(err)
	}
	return req
}

// requestWithDPoPAuthMissingProof carries a valid DPoP-scheme Authorization header but no DPoP
// proof header, exercising the "access token present, proof absent" path.
func requestWithDPoPAuthMissingProof(t *testing.T, url string, keyBytes []byte, scopes []string, exp time.Time) *http.Request {
	req := createRequestWithAccessTokenAndDPoP(t, url, keyBytes, scopes, exp)
	req.Header.Del("DPoP")
	return req
}

func TestDPoPEnforcer(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	p := createPEPAt(t, server.URL)

	dpopEnforcer := &pep.EnforcerAuthorizationDPoP{}
	mux.HandleFunc("/public", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("public"))
	})

	mux.HandleFunc("/dpop",
		p.GuardedHandlerFunc(dpopEnforcer, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("dpop"))
		}),
	)

	client := server.Client()

	tests := []struct {
		scenario       string
		url            string
		expectedStatus int
		expectedBody   string
		challenge      string
		noBody         bool
		request        *http.Request
	}{
		{scenario: "public access is always possible", url: "/public", expectedStatus: http.StatusOK, expectedBody: "public"},
		// RFC 9449 §7.1, Figure 15: without credentials, 401 with a challenge without error code and no error
		// body (RFC 6750 §3.1).
		{scenario: "fail without dpop+authorization", url: "/dpop", expectedStatus: http.StatusUnauthorized, challenge: `DPoP algs="ES256"`, noBody: true},
		{
			scenario:       "fail withoit dpop, but with bearer authorization",
			url:            "/dpop",
			expectedStatus: http.StatusBadRequest,
			request:        createRequestWithAccessToken(t, server.URL+"/dpop", []byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour)),
		},
		// RFC 9449 §7.1: a missing proof is invalid_dpop_proof in a 401 challenge; 400 is for malformed
		// credentials only (RFC 6750 §3.1).
		{
			scenario:       "fail with dpop authorization but missing dpop proof",
			url:            "/dpop",
			expectedStatus: http.StatusUnauthorized,
			challenge:      `DPoP error="invalid_dpop_proof", error_description="no DPoP proof", algs="ES256"`,
			request:        requestWithDPoPAuthMissingProof(t, server.URL+"/dpop", []byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour)),
		},
		{
			scenario:       "success",
			url:            "/dpop",
			expectedStatus: http.StatusOK,
			expectedBody:   "dpop",
			request:        createRequestWithAccessTokenAndDPoP(t, server.URL+"/dpop", []byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			req := tt.request
			if req == nil {
				var err error
				req, err = http.NewRequest(http.MethodGet, server.URL+tt.url, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}
			if tt.challenge != "" && resp.Header.Get("WWW-Authenticate") != tt.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", resp.Header.Get("WWW-Authenticate"), tt.challenge)
			}

			if tt.noBody {
				if body, _ := io.ReadAll(resp.Body); len(body) != 0 {
					t.Errorf("expected no body, got %q", body)
				}
				return
			}
			if tt.expectedBody == "" {
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, string(body))
			}
		})
	}
}

func TestAccessToken(t *testing.T) {
	accessToken, err := createTestAccessToken([]byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour), "test")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Access token: %s", accessToken)

	parsedToken, err := createPEP(t).VerifyAccessToken(accessToken)
	if err != nil {
		t.Fatalf("Failed to parse access token: %s", err)
	}

	if got := parsedToken.Thumbprint(); got != "test" {
		t.Fatalf("Expected thumbprint %s, got %s", "test", got)
	}
}

// RFC 6750 section 3.1: an access token that is expired or otherwise invalid is 401 invalid_token, under a challenge of
// the scheme the client used, and the reason stays with the server (server rule 2).
func TestRFC6750_3_1_AnInvalidBearerTokenIsRefusedWith401InvalidToken(t *testing.T) {
	assertInvalidToken(t, &pep.EnforcerAuthorizationBearer{}, createRequestWithAccessToken, `Bearer error="invalid_token", error_description="invalid access token"`)
}

// RFC 9449 section 7.1 applies RFC 6750 section 3.1 to the DPoP scheme.
func TestRFC9449_7_1_AnInvalidDPoPTokenIsRefusedWith401InvalidToken(t *testing.T) {
	assertInvalidToken(t, &pep.EnforcerAuthorizationDPoP{}, createRequestWithAccessTokenAndDPoP, `DPoP error="invalid_token", error_description="invalid access token", algs="ES256"`)
}

func assertInvalidToken(t *testing.T, enforcer pep.Enforcer, request func(*testing.T, string, []byte, []string, time.Time) *http.Request, challenge string) {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	p := createPEPAt(t, server.URL)
	mux.HandleFunc("/guarded", p.GuardedHandlerFunc(enforcer, func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran")
	}))

	resp, err := server.Client().Do(request(t, server.URL+"/guarded", []byte(privateJWK1), []string{"read"}, time.Now().Add(-time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != challenge {
		t.Errorf("WWW-Authenticate = %s", got)
	}
	var denial struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&denial); err != nil {
		t.Fatal(err)
	}
	if denial.Code != "invalid_token" || denial.Description != "invalid access token" {
		t.Errorf("denial = %+v", denial)
	}
}

// A query can carry what the log must not hold, as a forwarded callback's code does.
func TestServerRule14_ADeniedRequestIsLoggedWithoutItsQuery(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	p := createPEP(t)
	guarded := p.GuardedHandlerFunc(&pep.EnforcerDeny{}, func(http.ResponseWriter, *http.Request) {})
	guarded(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://example.com/cb?code=code-value", nil))
	if strings.Contains(logs.String(), "code-value") {
		t.Errorf("the log holds the query: %s", logs.String())
	}
}
