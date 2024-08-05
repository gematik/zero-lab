package pep_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pep"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestOauth2Guard(t *testing.T) {
	prk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prkJwk, _ := jwk.FromRaw(prk)
	prkJwk.Set(jwk.KeyIDKey, "test1")
	prkJwk.Set(jwk.AlgorithmKey, jwa.ES256)
	jwks := jwk.NewSet()
	jwks.AddKey(prkJwk)

	jwksJSON, _ := json.Marshal(jwks)
	t.Logf("jwks: %s", jwksJSON)

	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256, prkJwk))
	t.Logf("signed token: %s", signed)

	og, _ := pep.NewOAuth2Guard(func() (jwk.Set, error) { return jwks, nil }, *slog.Default())
	err := og.VerifyJWTToken(string(signed))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
