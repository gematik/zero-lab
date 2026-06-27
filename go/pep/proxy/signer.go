package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// sessionSigner mints the DPoP proof for an outbound API request. S4's implementation (bffSigner) signs with
// the session's BFF-held key; the T3 stage (docs/pdp-backend.md §10) swaps in a browser-relaying signer.
type sessionSigner interface {
	dpopProof(req *http.Request, accessToken string, key jwk.Key) (string, error)
}

type bffSigner struct{}

func (bffSigner) dpopProof(req *http.Request, accessToken string, key jwk.Key) (string, error) {
	pk, err := dpop.FromJWK(key)
	if err != nil {
		return "", fmt.Errorf("wrap dpop key: %w", err)
	}
	tok, err := dpop.NewBuilder().HttpRequest(req).AccessTokenHashFrom(accessToken).Build()
	if err != nil {
		return "", fmt.Errorf("build dpop proof: %w", err)
	}
	return tok.Sign(pk)
}

// newSessionDPoPKey generates a per-session DPoP keypair and returns the private key plus its JSON-marshaled
// JWK for storage on the session.
func newSessionDPoPKey() (jwk.Key, []byte, error) {
	pk, err := dpop.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}
	js, err := json.Marshal(pk.JwkPrivate)
	if err != nil {
		return nil, nil, err
	}
	return pk.JwkPrivate, js, nil
}

func parseSessionDPoPKey(jwkJSON []byte) (jwk.Key, error) {
	return jwk.ParseKey(jwkJSON)
}
