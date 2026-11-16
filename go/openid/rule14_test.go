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
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// marker and numberMarker stand for a peer's input; an error that holds one carries it into a log (servers.md
// rule 14). The decoder quotes a member's name and a number it cannot hold.
const (
	marker       = "PEER-INPUT-7f3a"
	numberMarker = "987654321987"
)

// requireRefusedFor asserts err refuses for its fixed reason and quotes none of the input.
func requireRefusedFor(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), numberMarker) {
		t.Fatalf("the error quotes the input: %v", err)
	}
	if err.Error() != reason {
		t.Fatalf("got %v, want %q", err, reason)
	}
}

// Server rule 14: an ID token's claims that do not decode are named, not quoted; a member named twice still unwraps.
func TestServerRule14_IDTokenClaimsAreNotQuoted(t *testing.T) {
	for name, payload := range map[string]string{
		"a member twice":   `{"` + marker + `":1,"` + marker + `":2}`,
		"a number too big": `{"n":` + numberMarker + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			var claims struct {
				N uint8 `json:"n"`
			}
			raw := "a." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c"
			err := (&TokenResponse{IDTokenRaw: raw}).Claims(&claims)
			requireRefusedFor(t, err, "ID token claims: do not decode")
			if name == "a member twice" && !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Fatalf("got %v, want a duplicate name to unwrap", err)
			}
		})
	}
}

// Server rule 14: a claim of the wrong type is named by the claim, not by its value.
func TestServerRule14_ARefusedClaimIsNotQuoted(t *testing.T) {
	for _, raw := range []string{`"` + marker + `"`, `[1,"` + marker + `"]`, `{"` + marker + `":1}`} {
		_, err := numericDateClaim(jsontext.Value(raw))
		requireRefusedFor(t, err, "is no number")
		if !strings.HasPrefix(raw, `"`) {
			_, err = audienceClaim(jsontext.Value(raw))
			requireRefusedFor(t, err, "is no string or array of strings")
		}
	}
	_, err := stringClaim(jsontext.Value(numberMarker))
	requireRefusedFor(t, err, "is no string")
	_, err = parseClaims([]byte(`{"nonce":` + numberMarker + `}`))
	requireRefusedFor(t, err, "token claim nonce: is no string")
}

// Server rule 14: a key set's server is named by its status code, not by the reason phrase it sent.
func TestServerRule14_AKeySetStatusIsNotQuoted(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Status: "502 " + marker, Body: io.NopCloser(strings.NewReader(marker))}, nil
	})}
	_, err := newKeySetCache("https://idp.example/jwks", client).download(t.Context())
	requireRefusedFor(t, err, "status 502")
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
