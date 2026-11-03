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

package openid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxResponseBytes bounds what a provider can make a relying party read.
const maxResponseBytes = 1 << 20

// AuthorizationQuery is the query of an authorization request with PKCE, or the form of a pushed one.
func AuthorizationQuery(clientID, redirectURI string, scopes []string, login Login) url.Values {
	query := url.Values{}
	query.Set("client_id", clientID)
	query.Set("redirect_uri", login.RedirectFor(redirectURI))
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", login.State)
	query.Set("nonce", login.Nonce)
	query.Set("code_challenge", S256Challenge(login.Verifier))
	query.Set("code_challenge_method", CodeChallengeMethodS256)
	return query
}

// Response is a provider's answer, read whole and within [maxResponseBytes].
type Response struct {
	Status int
	Body   []byte
}

// PostForm posts a form to a provider's endpoint.
func PostForm(ctx context.Context, client *http.Client, endpoint string, form url.Values) (*Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json, */*")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%s: response larger than %d bytes", endpoint, maxResponseBytes)
	}
	return &Response{Status: response.StatusCode, Body: body}, nil
}

// ParseTokenResponse decodes a token response. Entra ID writes expires_in as a string, which is tolerated.
func ParseTokenResponse(body []byte) (*TokenResponse, error) {
	response := new(TokenResponse)
	if err := json.Unmarshal(body, response); err == nil {
		return response, nil
	}
	var fallback struct {
		TokenResponse
		ExpiresIn int `json:"expires_in,string"`
	}
	if err := json.Unmarshal(body, &fallback); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	fallback.TokenResponse.ExpiresIn = fallback.ExpiresIn
	return &fallback.TokenResponse, nil
}
