package pep_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
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

	next := func(ctx pep.Context) {
		t.Fatal("next handler should not be called")
	}

	denyCalled := false
	deny := func(ctx pep.Context, err pep.Error) {
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

	asJson, err := json.Marshal(eh)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %s", err)
	}
	t.Logf("Marshalled JSON: %s", asJson)
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
	mux.HandleFunc("GET /public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public"))
	})

	mux.HandleFunc("GET /private",
		p.GuardedHandlerFunc(denyAllEnforcer, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("private"))
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

	mux.HandleFunc("GET /api-key", p.GuardedHandlerFunc(customEnforcer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("protected-by-api-key"))
	}))

	anyOfEnforcer := pep.EnforcerAnyOf{
		TypeVal: pep.EnforcerTypeAnyOf,
		EnforcerHolders: []pep.EnforcerHolder{
			{&pep.EnforcerDeny{TypeVal: pep.EnforcerTypeDeny}},
			{customEnforcer},
		},
	}

	mux.HandleFunc("GET /any-of", p.GuardedHandlerFunc(anyOfEnforcer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("any-of"))
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
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public"))
	})

	mux.HandleFunc("/read",
		p.GuardedHandlerFunc(enforcerRead, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("read"))
		}),
	)

	enforcerWrite := new(pep.EnforcerHolder)
	if err := json.Unmarshal([]byte(`{"type":"AllOf","enforcers":[{"type":"AuthorizationBearer"},{"type":"Scope","scope":"write"}]}`), enforcerWrite); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %s", err)
	}

	mux.HandleFunc("/write",
		p.GuardedHandlerFunc(enforcerWrite, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("write"))
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
		{url: "/read", expectedStatus: http.StatusForbidden, request: createRequestWithAccessToken(t, server.URL+"/read", []byte(privateJWKUnknown), []string{"read"}, time.Now().Add(time.Hour))},
		{url: "/read", expectedStatus: http.StatusForbidden, request: createRequestWithAccessToken(t, server.URL+"/read", []byte(privateJWK1), []string{"read"}, time.Now().Add(-2*time.Hour))},
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
	prk, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return "", err
	}

	token, err := jwt.NewBuilder().
		Claim("scope", scope).
		Audience([]string{"https://example.com"}).
		Expiration(exp).
		Build()
	if err != nil {
		return "", err
	}

	if jkt != "" {
		if err := token.Set("cnf", map[string]string{"jkt": jkt}); err != nil {
			return "", err
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), prk))
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
	proofKey, err := dpop.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
		return nil
	}

	accessToken, err := createTestAccessToken(keyBytes, scopes, exp, proofKey.Thumbprint)
	if err != nil {
		t.Fatal(err)
		return nil
	}

	proof, err := dpop.NewBuilder().
		Id(ksuid.New().String()).
		HttpMethod(http.MethodGet).
		HttpURI(url).
		AccessTokenHashFrom(accessToken).
		Build()
	if err != nil {
		t.Fatal(err)
		return nil
	}

	signedProof, err := proof.Sign(proofKey)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
		return nil
	}

	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", signedProof)

	return req
}

func TestDPoPEnforcer(t *testing.T) {
	p := createPEP(t)

	dpopEnforcer := &pep.EnforcerAuthorizationDPoP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public"))
	})

	mux.HandleFunc("/dpop",
		p.GuardedHandlerFunc(dpopEnforcer, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("dpop"))
		}),
	)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()

	tests := []struct {
		scenario       string
		url            string
		expectedStatus int
		expectedBody   string
		request        *http.Request
	}{
		{scenario: "public access is always possible", url: "/public", expectedStatus: http.StatusOK, expectedBody: "public"},
		{scenario: "fail without dpop+authorization", url: "/dpop", expectedStatus: http.StatusBadRequest},
		{
			scenario:       "fail withoit dpop, but with bearer authorization",
			url:            "/dpop",
			expectedStatus: http.StatusBadRequest,
			request:        createRequestWithAccessToken(t, server.URL+"/dpop", []byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour)),
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

	jwks, err := jwk.Parse([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}

	parsedToken, err := jwt.Parse([]byte(accessToken), jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		t.Fatalf("Failed to parse access token: %s", err)
	}

	cnf := new(map[string]interface{})
	if err := parsedToken.Get("cnf", cnf); err != nil {
		t.Fatalf("Failed to get cnf: %s", err)
	}

	if (*cnf)["jkt"] != "test" {
		t.Fatalf("Expected thumbprint %s, got %s", "test", (*cnf)["jkt"])
	}

}
