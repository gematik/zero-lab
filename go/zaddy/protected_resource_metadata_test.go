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

package zaddy

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"github.com/gematik/zero-lab/go/pep"
)

func parsePEPBlock(t *testing.T, block string) (App, error) {
	t.Helper()
	value, err := parseCaddyfilePEP(caddyfile.NewTestDispenser(block), nil)
	if err != nil {
		return App{}, err
	}
	var a App
	if err := json.Unmarshal(value.(httpcaddyfile.App).Value, &a); err != nil {
		t.Fatal(err)
	}
	return a, nil
}

// RFC 9728 Sections 2 and 3.2: protected_resource_metadata answers GET with the document the pep block's
// configuration states: resource, authorization server, header as the bearer method, the scopes and the members
// the deployment adds, a string among them quoted in backticks.
func TestRFC9728_3_2_TheMetadataIsServedFromTheConfiguration(t *testing.T) {
	a, err := parsePEPBlock(t, "pep {\n resource https://api.example.com\n authorization_server https://as.example.com\n"+
		" scopes_supported epa.read epa.write\n metadata_member zeta_asl_use `\"required\"`\n metadata_member x_profile `{\"v\":1}`\n}")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	handler, err := pep.NewProtectedResourceMetadataHandler(a.protectedResourceMetadata())
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := (ProtectedResourceMetadataHandler{handler: handler}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://api.example.com/.well-known/oauth-protected-resource", http.NoBody), nil); err != nil {
		t.Fatal(err)
	}
	want := `{"resource":"https://api.example.com","authorization_servers":["https://as.example.com"],"scopes_supported":["epa.read","epa.write"],` +
		`"bearer_methods_supported":["header"],"x_profile":{"v":1},"zeta_asl_use":"required"}`
	if body, _ := io.ReadAll(w.Body); w.Code != http.StatusOK || string(body) != want {
		t.Errorf("%d %s\nwant %s", w.Code, body, want)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
}

// RFC 9728 Section 2: a configuration whose added member pep would refuse (a typed name, a value that is not one JSON
// text) or whose scopes are malformed is refused when Caddy validates it.
func TestRFC9728_2_ACollidingOrMalformedMetadataMemberIsRefused(t *testing.T) {
	base := "pep {\n resource https://api.example.com\n authorization_server https://as.example.com\n"
	for name, line := range map[string]string{
		"resource":                 " metadata_member resource `\"https://evil.example\"`",
		"authorization_servers":    " metadata_member authorization_servers `[\"https://evil.example\"]`",
		"scopes_supported":         " metadata_member scopes_supported `[\"x\"]`",
		"bearer_methods_supported": " metadata_member bearer_methods_supported `[\"query\"]`",
		"jwks_uri":                 " metadata_member jwks_uri `\"https://evil.example/jwks\"`",
		"unquoted string":          " metadata_member zeta_asl_use required",
		"two texts":                " metadata_member zeta_asl_use `\"a\" \"b\"`",
		"duplicate name in value":  " metadata_member x `{\"a\":1,\"a\":2}`",
		"scope with quote":         " scopes_supported `a\"b`",
		"scope twice":              " scopes_supported a a",
	} {
		t.Run(name, func(t *testing.T) {
			a, err := parsePEPBlock(t, base+line+"\n}")
			if err == nil {
				err = a.Validate()
			}
			if err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := parsePEPBlock(t, base+" metadata_member x `1`\n metadata_member x `2`\n}"); err == nil {
		t.Error("a member named twice was accepted")
	}
	if _, err := parsePEPBlock(t, base+" metadata_member x\n}"); err == nil {
		t.Error("a member without a value was accepted")
	}
}

// The directive takes nothing: the document comes from the global pep block alone.
func TestProtectedResourceMetadataDirectiveTakesNoArguments(t *testing.T) {
	for block, ok := range map[string]bool{
		"protected_resource_metadata":                           true,
		"protected_resource_metadata extra":                     false,
		"protected_resource_metadata {\n resource https://x\n}": false,
	} {
		_, err := parseCaddyfileProtectedResourceMetadata(httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(block)})
		if (err == nil) != ok {
			t.Errorf("%q: %v", strings.ReplaceAll(block, "\n", " "), err)
		}
	}
}
