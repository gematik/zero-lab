package authzserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func createTestJwk() (jwk.Key, jwk.Set, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	jwkPrK, err := jwk.Import(privateKey)
	if err != nil {
		return nil, nil, err
	}

	jwkPrK.Set(jwk.KeyIDKey, "test-key")

	jwkPuK, _ := jwkPrK.PublicKey()
	jwks := jwk.NewSet()
	jwks.AddKey(jwkPuK)

	return jwkPrK, jwks, nil
}

func VerifyClientAssertionUsingJwks(jwks jwk.Set) func(assertion string) (*ClientAssertionClaims, error) {
	return func(assertion string) (*ClientAssertionClaims, error) {
		_, err := jwt.Parse(
			[]byte(assertion),
			jwt.WithAcceptableSkew(1*time.Minute),
			jwt.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)),
		)
		if err != nil {
			return nil, fmt.Errorf("parse assertion JWT: %w", err)
		}
		// token is valid, extract claims directly from base64 encoded payload
		claimsBase64 := strings.Split(assertion, ".")[1]
		claimsJson, err := base64.RawURLEncoding.DecodeString(claimsBase64)
		if err != nil {
			return nil, fmt.Errorf("decode claims from base64: %w", err)
		}
		claims := new(ClientAssertionClaims)
		if err := json.Unmarshal(claimsJson, claims); err != nil {
			return nil, fmt.Errorf("unmarshal assertion to claims: %w", err)
		}

		return claims, nil
	}
}

func TestJWTAssertion(t *testing.T) {
	// test assertion keys
	jwkPrk, jwkSet, err := createTestJwk()
	if err != nil {
		t.Fatalf("Failed to create test JWK: %v", err)
	}

	config := Config{
		VerifyClientAssertionFunc: VerifyClientAssertionUsingJwks(jwkSet),
	}

	server, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	nonce, err := server.nonceService.Get()
	if err != nil {
		t.Fatalf("Failed to get nonce: %v", err)
	}

	dpopPrK, err := dpop.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to create DPoP private key: %v", err)
	}

	assertion := jwt.New()
	assertion.Set(jwt.AudienceKey, "https://example.com")
	assertion.Set(jwt.IssuerKey, "https://example.com")
	assertion.Set(jwt.SubjectKey, "sub")
	assertion.Set(jwt.IssuedAtKey, time.Now().Unix())
	assertion.Set(jwt.ExpirationKey, time.Now().Add(5*time.Minute).Unix())
	assertion.Set("nonce", nonce)
	assertion.Set("cnf", map[string]string{"jkt": dpopPrK.Thumbprint})
	assertion.Set("urn:telematik:client-self-assessment", map[string]string{
		"product_id":      "test-product",
		"product_version": "1.0.0",
	})

	assertionBytes, err := jwt.Sign(assertion, jwt.WithKey(jwa.ES256(), jwkPrk))
	if err != nil {
		t.Fatalf("Failed to sign assertion: %v", err)
	}

	t.Logf("Assertion: %s", string(assertionBytes))

	req, _ := http.NewRequest("POST", "http://127.0.0.1/token", nil)
	// Simulate a server-received request: dpop.ParseRequest reconstructs the request URL
	// from Host + RequestURI (not URL), so set them to match the DPoP proof's htu.
	req.Host = "127.0.0.1"
	req.RequestURI = "/token"
	resp := httptest.NewRecorder()

	dpopToken, err := dpop.NewBuilder().
		HttpRequest(req).
		Nonce(nonce).
		Build()
	if err != nil {
		t.Fatalf("Failed to create DPoP token: %v", err)
	}

	dpopTokenSigned, err := dpopToken.Sign(dpopPrK)
	if err != nil {
		t.Fatalf("Failed to sign DPoP token: %v", err)
	}

	t.Logf("DPoP token: %s", string(dpopTokenSigned))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.Header.Set(dpop.DPoPHeaderName, string(dpopTokenSigned))
	req.Form = make(map[string][]string)
	req.Form.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.Form.Add("assertion", string(assertionBytes))
	encodedForm := req.Form.Encode()
	req.Body = io.NopCloser(strings.NewReader(encodedForm))

	// The assertion/nonce/DPoP validation pipeline should pass; the JWT Bearer grant
	// itself is not yet implemented, so we expect to reach its not_implemented stub.
	err = server.TokenEndpoint(resp, req)
	if err == nil {
		t.Fatal("expected JWT Bearer grant to reach the not_implemented stub, got nil")
	}
	authzErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if authzErr.Code != "not_implemented" {
		t.Fatalf("validation pipeline should pass and reach not_implemented; got %q: %s",
			authzErr.Code, authzErr.Description)
	}
}
