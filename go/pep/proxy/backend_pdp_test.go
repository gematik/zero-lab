package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func testSigningKey(t *testing.T) jwk.Key {
	t.Helper()
	prk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, _ := jwk.Import(prk)
	k.Set(jwk.KeyIDKey, "test-pep-client")
	return k
}

func TestPDPClientAssertionClaims(t *testing.T) {
	b := &pdpBackend{
		cfg:  PDPConfig{ASIssuer: "https://as.example", ClientID: "pep-client", SigningKey: testSigningKey(t)},
		meta: asMetadata{Issuer: "https://as.example"}, // no NonceEndpoint → skip nonce fetch
	}
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{ID: "s1", DPoPKeyJWK: jwkJSON}

	assertion, err := b.clientAssertion(context.Background(), sess)
	if err != nil {
		t.Fatalf("clientAssertion: %v", err)
	}
	pub, _ := b.cfg.SigningKey.PublicKey()
	tok, err := jwt.Parse([]byte(assertion), jwt.WithKey(jwa.ES256(), pub))
	if err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
	if iss, _ := tok.Issuer(); iss != "pep-client" {
		t.Errorf("iss = %q", iss)
	}
	if aud, _ := tok.Audience(); len(aud) != 1 || aud[0] != "https://as.example" {
		t.Errorf("aud = %v", aud)
	}
	var cnf map[string]any
	if err := tok.Get("cnf", &cnf); err != nil {
		t.Fatalf("no cnf: %v", err)
	}
	if s, _ := cnf["jkt"].(string); s == "" {
		t.Errorf("cnf.jkt missing: %v", cnf)
	}
}
