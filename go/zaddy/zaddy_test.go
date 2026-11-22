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
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	"github.com/gematik/zero-lab/go/dpop"
)

func logTo(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

// servers.md rule 3: replay detection in one replica's memory is not the default it seems; zaddy says so.
func TestServersRule3_WithoutSharedStorageReplayDetectionIsLoggedAsPerReplica(t *testing.T) {
	for _, setting := range []string{"", dpopReplaysMemory} {
		var buf bytes.Buffer
		a := &App{DPoPReplays: setting, logger: logTo(&buf)}
		if _, ok := a.dpopReplays().(*dpop.MemoryReplays); !ok {
			t.Fatalf("%q: not in memory", setting)
		}
		if !strings.Contains(buf.String(), `"level":"WARN"`) || !strings.Contains(buf.String(), "DPoP replay detection holds for this replica only") {
			t.Fatalf("%q: logged %s", setting, buf.String())
		}
	}
}

func TestServersRule3_DPoPReplaysStorageKeepsReplaysInCaddyStorage(t *testing.T) {
	var buf bytes.Buffer
	dir := t.TempDir()
	a := &App{DPoPReplays: dpopReplaysStorage, logger: logTo(&buf), storage: replicaStorage(dir)}
	replays, ok := a.dpopReplays().(*storageReplays)
	if !ok {
		t.Fatal("not in storage")
	}
	t.Cleanup(a.stopReplays)
	if strings.Contains(buf.String(), "this replica only") || !strings.Contains(buf.String(), dir) {
		t.Fatalf("logged %s", buf.String())
	}
	if replays.storage != a.storage {
		t.Fatal("replays not in the app's storage")
	}
}

func TestDPoPReplays_CaddyfileOptionAndValidation(t *testing.T) {
	d := caddyfile.NewTestDispenser("pep {\n resource https://api.example.com\n jwks_path jwks.json\n dpop_replays storage\n}")
	value, err := parseCaddyfilePEP(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	var a App
	if err := json.Unmarshal(value.(httpcaddyfile.App).Value, &a); err != nil {
		t.Fatal(err)
	}
	if a.DPoPReplays != dpopReplaysStorage {
		t.Fatalf("dpop_replays %q", a.DPoPReplays)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	a.DPoPReplays = "redis"
	if err := a.Validate(); err == nil {
		t.Fatal("accepted an unknown dpop_replays")
	}
}

// RFC 9700 Section 4.10.2: zaddy refuses a configuration without a resource, as no token's audience could be
// checked; RFC 9068 Section 4: accept_untyped_access_tokens is the operator's opt-in for untyped tokens, off unless
// named.
func TestRFC9700_4_10_2_ZaddyRefusesAConfigurationWithoutAResource(t *testing.T) {
	parse := func(t *testing.T, block string) App {
		t.Helper()
		value, err := parseCaddyfilePEP(caddyfile.NewTestDispenser(block), nil)
		if err != nil {
			t.Fatal(err)
		}
		var a App
		if err := json.Unmarshal(value.(httpcaddyfile.App).Value, &a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	without := parse(t, "pep {\n jwks_path jwks.json\n}")
	if err := without.Validate(); err == nil {
		t.Error("a configuration without resource was accepted")
	}
	typed := parse(t, "pep {\n resource https://api.example.com\n jwks_path jwks.json\n}")
	if err := typed.Validate(); err != nil || typed.AcceptUntypedAccessTokens {
		t.Errorf("default: %v, untyped accepted %v", err, typed.AcceptUntypedAccessTokens)
	}
	untyped := parse(t, "pep {\n resource https://api.example.com\n jwks_path jwks.json\n accept_untyped_access_tokens\n}")
	if !untyped.AcceptUntypedAccessTokens {
		t.Error("accept_untyped_access_tokens was not taken")
	}
	if _, err := parseCaddyfilePEP(caddyfile.NewTestDispenser("pep {\n accept_untyped_access_tokens yes\n}"), nil); err == nil {
		t.Error("accept_untyped_access_tokens took an argument")
	}
}

// servers.md rule 30: zaddy's egress client takes the forward proxy of the environment, with the credentials file the
// pep block names.
func TestServerRule30_ZaddyTakesTheProxyCredentialsFileFromItsConfiguration(t *testing.T) {
	value, err := parseCaddyfilePEP(caddyfile.NewTestDispenser("pep {\n resource https://api.example.com\n jwks_path jwks.json\n egress_proxy_credentials_path /run/secrets/proxy\n}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var a App
	if err := json.Unmarshal(value.(httpcaddyfile.App).Value, &a); err != nil {
		t.Fatal(err)
	}
	if a.EgressProxyCredentialsPath != "/run/secrets/proxy" {
		t.Errorf("egress_proxy_credentials_path = %q", a.EgressProxyCredentialsPath)
	}
}
