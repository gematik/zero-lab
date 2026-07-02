package josebp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

func signedTokenWithAlg(t *testing.T, alg string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tok, err := NewJWTBuilder().
		Header("alg", alg).
		Header("typ", "JWT").
		Claim("sub", "test").
		Sign(sha256.New(), brainpool.SignFuncPrivateKey(key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestVerifyRejectsAlgCurveMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// alg ES384/BP384R1/ES512 all imply a non-256-bit curve, but the key is
	// brainpoolP256r1. Each must be rejected before signature verification.
	for _, alg := range []string{AlgorithmNameES384, AlgorithmNameBP384R1, AlgorithmNameES512, AlgorithmNameBP512R1} {
		tok := signedTokenWithAlg(t, alg, key)
		if _, err := ParseToken(tok, WithEcdsaPublicKey(&key.PublicKey)); err == nil {
			t.Fatalf("alg %s with P256r1 key was accepted", alg)
		}
	}
}

func TestVerifyAcceptsMatchingAlg(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Both ES256 and BP256R1 are valid for a 256-bit curve in the gematik stack.
	for _, alg := range []string{AlgorithmNameES256, AlgorithmNameBP256R1} {
		tok := signedTokenWithAlg(t, alg, key)
		if _, err := ParseToken(tok, WithEcdsaPublicKey(&key.PublicKey)); err != nil {
			t.Fatalf("alg %s with P256r1 key rejected: %v", alg, err)
		}
	}
}
