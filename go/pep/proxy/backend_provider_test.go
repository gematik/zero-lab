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
	"context"
	"testing"

	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/openid/providers"
)

type recordingClient struct {
	openid.Client
	login openid.Login
}

func (c *recordingClient) Exchange(_ context.Context, login openid.Login, _ string) (*openid.TokenResponse, error) {
	c.login = login
	return &openid.TokenResponse{IDTokenRaw: "e30.e30.e30"}, nil //nolint:gosec // empty JSON parts, not a credential
}

// The clients bind the ID token to the login by its nonce, so the session's nonce has to reach them.
func TestCompleteHandsTheSessionsNonceToTheExchange(t *testing.T) {
	client := &recordingClient{}
	backend := NewProviderBackend(providers.New(nil, providers.Provider{Issuer: "https://op", Client: client}))
	session := &Session{IDPIss: "https://op", Nonce: "the-nonce", CodeVerifier: "v"}
	if err := backend.Complete(t.Context(), session, "code"); err != nil {
		t.Fatal(err)
	}
	if client.login.Nonce != "the-nonce" || client.login.Verifier != "v" {
		t.Errorf("login %+v", client.login)
	}
}
