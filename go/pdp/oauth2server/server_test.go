package oauth2server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func createTestJwk() (jwk.Key, jwk.Set, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	jwkPrK, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, err
	}
	jwkPuK, _ := jwkPrK.PublicKey()
	jwks := jwk.NewSet()
	jwks.AddKey(jwkPuK)

	return jwkPuK, jwks, nil
}

func VerifyClientAssertionUsingJwks(jwks jwk.Set) func(assertion string) (map[string]interface{}, error) {
	return func(assertion string) (map[string]interface{}, error) {
		return nil, nil
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

	assertion := jwt.New()
	assertion.Set(jwt.AudienceKey, "https://example.com")
	assertion.Set(jwt.IssuerKey, "https://example.com")

	assertionBytes, err := jwt.Sign(assertion, jwt.WithKey(jwa.ES256, jwkPrk))
	if err != nil {
		t.Fatalf("Failed to sign assertion: %v", err)
	}

	echoServer := echo.New()

	req, _ := http.NewRequest("POST", "http://127.0.0.1/token", nil)
	resp := httptest.NewRecorder()

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Form = make(map[string][]string)
	req.Form.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req.Form.Add("assertion", string(assertionBytes))
	encodedForm := req.Form.Encode()
	req.Body = io.NopCloser(strings.NewReader(encodedForm))

	e := echoServer.NewContext(req, resp)
	if err := server.TokenEndpoint(e); err != nil {
		t.Fatalf("Failed to call TokenEndpoint: %v", err)
	}
}
