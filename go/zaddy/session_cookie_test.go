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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/gematik/zero-lab/go/pep"
)

// Server rule 17: a policy with a SessionCookie enforcer, at any depth, is refused: zaddy has no session
// revocations, and a snapshot would admit a signed-out session for its lifetime. Other policies are accepted.
func TestServerRule17_ZaddyRefusesASessionCookiePolicy(t *testing.T) {
	var nested pep.EnforcerHolder
	if err := nested.UnmarshalJSON([]byte(`{"type":"AnyOf","enforcers":[{"type":"SessionCookie","cookie_name":"SID","key_path":"/k"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := refuseSessionCookie(&nested); err == nil || !strings.Contains(err.Error(), "forward_auth") {
		t.Errorf("a SessionCookie enforcer inside an any_of: err = %v", err)
	}
	bearer := &pep.EnforcerHolder{Enforcer: &pep.EnforcerAllOf{EnforcerHolders: []pep.EnforcerHolder{{Enforcer: &pep.EnforcerAuthorizationBearer{}}}}}
	if err := refuseSessionCookie(bearer); err != nil {
		t.Errorf("a bearer policy: %v", err)
	}
	if err := refuseSessionCookie((*pep.EnforcerHolder)(nil)); err != nil {
		t.Errorf("no policy: %v", err)
	}
}

// zaddy keeps no database: a Caddyfile that still names the revocations' database stops the start and says
// why, rather than being read as if the revocations were followed.
func TestServerRule17_TheRevocationsDatabaseIsRefusedAsGone(t *testing.T) {
	for _, line := range []string{
		"revocations_database_url postgres://revocations.example/kv",
		"revocations_database_plaintext_accepted true",
		"revocations_database_tls_ca_path /ca.pem",
	} {
		_, err := parseCaddyfilePEP(caddyfile.NewTestDispenser("pep {\n resource https://api.example.com\n jwks_path jwks.json\n "+line+"\n}"), nil)
		if err == nil || !strings.Contains(err.Error(), "keeps no database") {
			t.Errorf("%s: err = %v", strings.Fields(line)[0], err)
		}
	}
}
