package jwxbp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func curves() []struct {
	name  string
	alg   jwa.SignatureAlgorithm
	curve elliptic.Curve
} {
	return []struct {
		name  string
		alg   jwa.SignatureAlgorithm
		curve elliptic.Curve
	}{
		{"BP256R1", BP256R1, brainpool.P256r1()},
		{"BP384R1", BP384R1, brainpool.P384r1()},
		{"BP512R1", BP512R1, brainpool.P512r1()},
	}
}

// TestJWSRoundTrip signs and verifies with jwx for every brainpool curve.
func TestJWSRoundTrip(t *testing.T) {
	for _, tc := range curves() {
		t.Run(tc.name, func(t *testing.T) {
			prk, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("hello brainpool via jwx")

			signed, err := jws.Sign(payload, jws.WithKey(tc.alg, prk))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, err := jws.Verify(signed, jws.WithKey(tc.alg, &prk.PublicKey))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if string(got) != string(payload) {
				t.Fatalf("payload mismatch: %q", got)
			}

			// negative: a different key must not verify
			other, _ := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if _, err := jws.Verify(signed, jws.WithKey(tc.alg, &other.PublicKey)); err == nil {
				t.Fatal("verify unexpectedly succeeded with wrong key")
			}
		})
	}
}

// TestJWTRoundTrip exercises the high-level jwt API with a brainpool key.
func TestJWTRoundTrip(t *testing.T) {
	prk, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewBuilder().
		Issuer("https://idp.example").
		Subject("user-123").
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(BP256R1, prk))
	if err != nil {
		t.Fatalf("jwt sign: %v", err)
	}
	parsed, err := jwt.Parse(signed, jwt.WithKey(BP256R1, &prk.PublicKey))
	if err != nil {
		t.Fatalf("jwt parse: %v", err)
	}
	if iss, _ := parsed.Issuer(); iss != "https://idp.example" {
		t.Fatalf("iss = %q", iss)
	}
	if sub, _ := parsed.Subject(); sub != "user-123" {
		t.Fatalf("sub = %q", sub)
	}
}

// TestJWKPath proves the jwk machinery handles brainpool keys: import a brainpool key, round-trip
// it through JWK JSON, and verify a token with the parsed key (the JWKS verification path).
func TestJWKPath(t *testing.T) {
	prk, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubJWK, err := jwk.Import(&prk.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Import brainpool public key: %v", err)
	}
	jsonBytes, err := json.Marshal(pubJWK)
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := jwk.ParseKey(jsonBytes)
	if err != nil {
		t.Fatalf("jwk.ParseKey brainpool JWK: %v", err)
	}

	payload := []byte("verify-with-jwk")
	signed, err := jws.Sign(payload, jws.WithKey(BP256R1, prk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(signed, jws.WithKey(BP256R1, parsedKey)); err != nil {
		t.Fatalf("verify with parsed JWK: %v", err)
	}
}

// TestInteropLegacy proves the jwx signer/verifier are wire-compatible with the existing
// brainpool JOSE implementation (same r‖s encoding): a token signed by brainpool.JWTBuilder
// verifies via jwx, and a jwx-signed token verifies via brainpool.ParseToken.
func TestInteropLegacy(t *testing.T) {
	prk, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// legacy sign -> jwx verify
	h, err := brainpool.HashFunctionForCurve(prk.Curve)
	if err != nil {
		t.Fatal(err)
	}
	legacyToken, err := brainpool.NewJWTBuilder().
		Header("alg", brainpool.AlgorithmNameBP256R1).
		Header("typ", "JWT").
		Claim("iss", "legacy").
		Sign(h, brainpool.SignFuncPrivateKey(prk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(legacyToken, jws.WithKey(BP256R1, &prk.PublicKey)); err != nil {
		t.Fatalf("jwx failed to verify a legacy brainpool token: %v", err)
	}

	// jwx sign -> legacy verify (payload must be JSON claims for brainpool.ParseToken)
	jwxToken, err := jws.Sign([]byte(`{"iss":"from-jwx"}`), jws.WithKey(BP256R1, prk))
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &brainpool.JSONWebKey{Key: &prk.PublicKey}
	if _, err := brainpool.ParseToken(jwxToken, brainpool.WithKey(pubKey)); err != nil {
		t.Fatalf("legacy brainpool failed to verify a jwx token: %v", err)
	}
}
