package oidf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// TestEntityStatementHook checks that a registered hook injects values into the served entity statement,
// that repeated signings do not accumulate, and that the relying party's base statement is untouched.
func TestEntityStatementHook(t *testing.T) {
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigKey, err := jwk.Import(prk)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sigKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	jwks := &Jwks{Keys: jwk.NewSet()}
	jwks.Keys.AddKey(pub)

	rp := &RelyingParty{
		cfg:           &RelyingPartyConfig{FedMasterURL: "https://fedmaster.example", SignKid: "sign-kid"},
		sigPrivateKey: sigKey,
		entityStatement: &EntityStatement{
			Issuer:  "https://rp.example",
			Subject: "https://rp.example",
			Jwks:    jwks,
			Metadata: &Metadata{
				OpenidRelyingParty: &OpenIDRelyingPartyMetadata{
					RedirectURIs: []string{"https://rp.example/cb"},
				},
			},
		},
	}

	const injected = "https://product.example/as-cb"
	rp.AddEntityStatementHook(func(es *EntityStatement) {
		orp := es.Metadata.OpenidRelyingParty
		orp.RedirectURIs = append(orp.RedirectURIs, injected)
	})

	servedRedirects := func() []string {
		signed, err := rp.SignEntityStatement()
		if err != nil {
			t.Fatal(err)
		}
		msg, err := jws.Parse(signed)
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Metadata struct {
				OpenidRelyingParty struct {
					RedirectURIs []string `json:"redirect_uris"`
				} `json:"openid_relying_party"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(msg.Payload(), &claims); err != nil {
			t.Fatal(err)
		}
		return claims.Metadata.OpenidRelyingParty.RedirectURIs
	}

	first := servedRedirects()
	if !slices.Contains(first, injected) {
		t.Fatalf("hook redirect not in served entity statement: %v", first)
	}
	if second := servedRedirects(); len(second) != len(first) {
		t.Errorf("redirect_uris accumulated across signings: %d then %d", len(first), len(second))
	}
	if base := rp.entityStatement.Metadata.OpenidRelyingParty.RedirectURIs; len(base) != 1 {
		t.Errorf("base entity statement mutated by hook: %v", base)
	}
}
