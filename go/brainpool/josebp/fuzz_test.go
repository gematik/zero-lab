package josebp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// JWK unmarshalling must never panic on malformed JSON.
func FuzzJSONWebKeyUnmarshal(f *testing.F) {
	f.Add([]byte(`{"kty":"EC","crv":"BP-256","x":"AA","y":"AA"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var jwk JSONWebKey
		_ = json.Unmarshal(data, &jwk)
	})
}

// Token parsing/verification must never panic on malformed input.
func FuzzParseToken(f *testing.F) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("a.b.c"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseToken(data, WithEcdsaPublicKey(&key.PublicKey))
	})
}
