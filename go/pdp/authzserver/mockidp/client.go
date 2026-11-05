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

//go:build mockidp

package mockidp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// mockClient is the AS-side openid.Client for the co-hosted mock OP. The PDP holds it in its provider registry
// like any upstream OP; ExchangeForIdentity does a real HTTP round-trip to the mock /token (co-hosted on the
// same server, reachable at runtime) and validates the returned id_token — exercising the genuine path.
type mockClient struct {
	issuer      string
	clientID    string
	redirectURI string
	keys        *jose.JSONWebKeySet
	http        *http.Client
}

var _ openid.Client = (*mockClient)(nil)

func (c *mockClient) Issuer() string { return c.issuer }

func (c *mockClient) AuthenticationURL(_ context.Context, login openid.Login) (string, error) {
	return c.issuer + "/auth?" + openid.AuthorizationQuery(c.clientID, c.redirectURI, []string{"openid"}, login).Encode(), nil
}

func (c *mockClient) Exchange(ctx context.Context, login openid.Login, code string) (*openid.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", login.Verifier)
	form.Set("client_id", c.clientID)
	form.Set("redirect_uri", login.RedirectFor(c.redirectURI))

	hc := c.http
	if hc == nil {
		hc = http.DefaultClient
	}
	response, err := openid.PostForm(ctx, hc, c.issuer+"/token", form)
	if err != nil {
		return nil, fmt.Errorf("mock token exchange: %w", err)
	}
	if response.Status != http.StatusOK {
		return nil, fmt.Errorf("mock token endpoint returned %d: %s", response.Status, response.Body)
	}
	tr := new(openid.TokenResponse)
	if err := json.Unmarshal(response.Body, tr); err != nil {
		return nil, fmt.Errorf("decode mock token response: %w", err)
	}
	payload, err := openid.VerifyJWS([]byte(tr.IDTokenRaw), c.keys, openid.VerifyOptions{RequireKeyAlgorithm: true})
	if err != nil {
		return nil, fmt.Errorf("verify mock id_token: %w", err)
	}
	checks := openid.IDTokenChecks{Issuer: c.issuer, ClientID: c.clientID, Nonce: login.Nonce, Now: time.Now()}
	if err := checks.Validate(payload); err != nil {
		return nil, fmt.Errorf("verify mock id_token: %w", err)
	}
	return tr, nil
}
