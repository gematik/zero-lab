package e2e

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// oauthError decodes an OAuth JSON error body and returns its "error" code, also asserting the
// response is application/json.
func oauthError(t *testing.T, resp *http.Response) string {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected application/json error, got %q: %s", ct, body)
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode oauth error: %v", err)
	}
	return e.Error
}

func TestRegression_MetadataContract(t *testing.T) {
	md := getMetadata(t, baseURL(t))

	for _, gt := range []string{
		"authorization_code", "refresh_token", "client_credentials",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
	} {
		if !slices.Contains(md.GrantTypesSupported, gt) {
			t.Errorf("grant_types_supported missing %q: %v", gt, md.GrantTypesSupported)
		}
	}
	if !slices.Equal(md.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", md.CodeChallengeMethodsSupported)
	}
	if !slices.Equal(md.ResponseTypesSupported, []string{"code"}) {
		t.Errorf("response_types_supported = %v, want [code]", md.ResponseTypesSupported)
	}
	for _, ep := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.JwksURI} {
		if !strings.HasPrefix(ep, md.Issuer) {
			t.Errorf("endpoint %q is not under issuer %q", ep, md.Issuer)
		}
	}
}

func TestRegression_ErrorFormat(t *testing.T) {
	base := baseURL(t)
	md := getMetadata(t, base)

	t.Run("unknown_path_404", func(t *testing.T) {
		resp := mustGet(t, httpClient(), base+"/definitely-not-a-route")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status %d, want 404", resp.StatusCode)
		}
		if code := oauthError(t, resp); code != "not_found" {
			t.Errorf("error = %q, want not_found", code)
		}
	})

	t.Run("wrong_method_405", func(t *testing.T) {
		// JWKS is GET-only; POST must yield 405 in OAuth JSON.
		resp, err := httpClient().Post(md.JwksURI, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("POST jwks: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", resp.StatusCode)
		}
		if code := oauthError(t, resp); code != "method_not_allowed" {
			t.Errorf("error = %q, want method_not_allowed", code)
		}
	})

	t.Run("nonce_head_mirrors_get", func(t *testing.T) {
		// net/http serves HEAD via the registered GET route, so HEAD /nonce returns 200 with an
		// empty body (the old special HEAD/Replay-Nonce handling was removed).
		req, _ := http.NewRequest(http.MethodHead, md.NonceEndpoint, nil)
		resp, err := httpClient().Do(req)
		if err != nil {
			t.Fatalf("HEAD nonce: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HEAD nonce status %d, want 200", resp.StatusCode)
		}
	})

	t.Run("unsupported_grant", func(t *testing.T) {
		resp, err := httpClient().PostForm(md.TokenEndpoint, map[string][]string{"grant_type": {"nope"}})
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", resp.StatusCode)
		}
		if code := oauthError(t, resp); code != "unsupported_grant_type" {
			t.Errorf("error = %q, want unsupported_grant_type", code)
		}
	})

	t.Run("bad_content_type", func(t *testing.T) {
		resp, err := httpClient().Post(md.TokenEndpoint, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d, want 400", resp.StatusCode)
		}
		if code := oauthError(t, resp); code != "invalid_request" {
			t.Errorf("error = %q, want invalid_request", code)
		}
	})
}

// TestRegression_OIDFEntityStatement validates the OpenID Federation entity statement served at
// /.well-known/openid-federation: it must be a self-signed entity-statement JWT whose signature
// verifies against its own embedded JWKS, with iss==sub, a validity window, authority_hints, and
// the expected metadata blocks.
func TestRegression_OIDFEntityStatement(t *testing.T) {
	base := baseURL(t)
	resp := mustGet(t, httpClient(), base+"/.well-known/openid-federation")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("OIDF entity statement not configured")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entity statement: status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/entity-statement+jwt") {
		t.Errorf("content-type = %q, want application/entity-statement+jwt", ct)
	}
	raw, _ := io.ReadAll(resp.Body)

	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT (%d segments)", len(parts))
	}
	var hdr struct{ Typ, Alg, Kid string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr.Typ != "entity-statement+jwt" {
		t.Errorf("header typ = %q, want entity-statement+jwt", hdr.Typ)
	}

	var es struct {
		Iss            string          `json:"iss"`
		Sub            string          `json:"sub"`
		Iat            int64           `json:"iat"`
		Exp            int64           `json:"exp"`
		AuthorityHints []string        `json:"authority_hints"`
		Jwks           json.RawMessage `json:"jwks"`
		Metadata       struct {
			FederationEntity   json.RawMessage `json:"federation_entity"`
			OpenidRelyingParty json.RawMessage `json:"openid_relying_party"`
		} `json:"metadata"`
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if err := json.Unmarshal(pb, &es); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	if es.Iss == "" || es.Iss != es.Sub {
		t.Errorf("entity statement must be self-issued: iss=%q sub=%q", es.Iss, es.Sub)
	}
	if es.Exp <= es.Iat {
		t.Errorf("invalid validity window: iat=%d exp=%d", es.Iat, es.Exp)
	}
	if len(es.AuthorityHints) == 0 {
		t.Error("authority_hints is empty (expected the federation master)")
	}
	if len(es.Metadata.FederationEntity) == 0 {
		t.Error("metadata.federation_entity missing")
	}
	if len(es.Metadata.OpenidRelyingParty) == 0 {
		t.Error("metadata.openid_relying_party missing")
	}

	// The statement is self-signed: verify against the JWKS it carries.
	keys, err := jwk.Parse(es.Jwks)
	if err != nil {
		t.Fatalf("parse embedded jwks: %v", err)
	}
	if _, err := jws.Verify(raw, jws.WithKeySet(keys, jws.WithInferAlgorithmFromKey(true))); err != nil {
		t.Fatalf("entity statement signature did not verify against its own jwks: %v", err)
	}
	t.Logf("OK: entity statement self-verifies — iss=%s alg=%s authority_hints=%v", es.Iss, hdr.Alg, es.AuthorityHints)
}
