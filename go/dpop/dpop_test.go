package dpop_test

import (
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
)

func TestSigning(t *testing.T) {
	privateKey, _ := dpop.NewPrivateKey()

	token := dpop.DPoP{
		HttpMethod: "GET",
		HttpURI:    "https://example.com/resource/1",
		IssuedAt:   time.Now(),
	}

	signed, err := token.Sign(privateKey)
	if err != nil {
		t.Error("expected nil, got ", err)
	}

	parsedToken, err := dpop.Parse(signed)

	if err != nil {
		t.Fatal("expected nil, got ", err)
	}

	t.Logf("%+v", parsedToken)
}
