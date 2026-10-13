// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
