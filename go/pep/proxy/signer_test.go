package proxy

import (
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/dpop"
)

func TestBffSignerProof(t *testing.T) {
	priv, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(jwkJSON) == 0 {
		t.Fatal("expected serialized key")
	}
	if _, err := parseSessionDPoPKey(jwkJSON); err != nil {
		t.Fatalf("parseSessionDPoPKey: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://api.example/protected", nil)
	proof, err := (bffSigner{}).dpopProof(req, "the-access-token", priv)
	if err != nil {
		t.Fatalf("dpopProof: %v", err)
	}
	parsed, err := dpop.Parse(proof)
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	if parsed.HttpMethod != "GET" || parsed.HttpURI != "https://api.example/protected" {
		t.Errorf("htm/htu = %s %s", parsed.HttpMethod, parsed.HttpURI)
	}
	ath, _ := dpop.CalculateAccessTokenHash("the-access-token")
	if parsed.AccessTokenHash != ath {
		t.Errorf("ath = %q, want %q", parsed.AccessTokenHash, ath)
	}
}
