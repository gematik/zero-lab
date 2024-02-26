package dpop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gematik/zero-lab/pkg/dpop"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestNewTokenId(t *testing.T) {
	_, err := dpop.NewToken(
		"",
		"GET",
		"https://example.com/resource/1",
		time.Now(),
		"",
		"",
	)
	if err == nil {
		t.Error("expected error, got nil")
	}

	token, err := dpop.NewToken(
		dpop.NewTokenId(),
		"GET",
		"https://example.com/resource/1",
		time.Now(),
		"",
		"",
	)
	if err != nil {
		t.Error("expected nil, got ", err)
	}
	t.Log(token)
}

func TestSigning(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(privateKey)

	token, err := dpop.NewToken(
		dpop.NewTokenId(),
		"GET",
		"https://example.com/resource/1",
		time.Now(),
		"",
		"",
	)
	if err != nil {
		t.Error("expected nil, got ", err)
	}

	signed, err := dpop.SignToken(token, jwkKey)
	if err != nil {
		t.Error("expected nil, got ", err)
	}

	dpopToken, err := dpop.ParseToken(signed)

	if err != nil {
		t.Fatal("expected nil, got ", err)
	}

	t.Logf("%+v", dpopToken)
}
