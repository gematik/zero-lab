package pep_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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
	//prkJwk.Set(jwk.AlgorithmKey, jwa.ES256)
	jwks := jwk.NewSet()
	jwks.AddKey(prkJwk)

	jwksJSON, _ := json.Marshal(jwks)
	t.Logf("jwks: %s", jwksJSON)

	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	signedToken, _ := jwt.Sign(tok, jwt.WithKey(jwa.ES256, prkJwk))
	t.Logf("signed token: %s", signedToken)

	thePep := pep.New()
	thePep.Jwks = jwks

	// Test the PEP with a valid token
	verifiedToken, err := thePep.VerifyJWTToken(string(signedToken))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("verified token: %s", verifiedToken)

	go func() {
		time.Sleep(3 * time.Second)
		t.Logf("stopping PEP")
		thePep.Stop()
	}()

	thePep.Start(context.TODO())
}
