package dpop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/libzero/dpop"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestSigning(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(privateKey)

	token := dpop.DPoP{
		HttpMethod: "GET",
		HttpURI:    "https://example.com/resource/1",
		IssuedAt:   time.Now(),
	}

	signed, err := token.Sign(jwkKey)
	if err != nil {
		t.Error("expected nil, got ", err)
	}

	parsedToken, err := dpop.Parse(signed)

	if err != nil {
		t.Fatal("expected nil, got ", err)
	}

	t.Logf("%+v", parsedToken)
}
