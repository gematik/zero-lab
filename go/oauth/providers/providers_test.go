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

package providers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

type fakeClient struct {
	oidc.Client
	issuer, kind string
}

func (f fakeClient) Issuer() string  { return f.issuer }
func (f fakeClient) Name() string    { return f.issuer }
func (f fakeClient) LogoURI() string { return "" }

func (f fakeClient) ProviderType() string { return f.kind }

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fakeKind(issuer string) Kind {
	return func(node *yaml.Node, _ Env) (Built, error) {
		var entries []struct {
			ClientID string `yaml:"client_id"`
		}
		if err := Decode(node, &entries); err != nil {
			return Built{}, err
		}
		return Built{Clients: []oidc.Client{fakeClient{issuer: issuer, kind: issuer}}}, nil
	}
}

func TestAnOutdatedKeyStopsTheStart(t *testing.T) {
	path := write(t, "gemidp:\n  - client_id: x\n")
	_, err := Load(path, Env{}, Kinds{"idpd": fakeKind("a")})
	if err == nil || !strings.Contains(err.Error(), `unknown key "gemidp"`) || !strings.Contains(err.Error(), "idpd") {
		t.Errorf("err = %v", err)
	}
}

func TestAnUnknownFieldInAnEntryStopsTheStart(t *testing.T) {
	path := write(t, "idpd:\n  - client_id: x\n    trust_bundle: y\n")
	if _, err := Load(path, Env{}, Kinds{"idpd": fakeKind("a")}); err == nil {
		t.Error("an unknown field")
	}
}

func TestTheFilesOrderDecidesTheDefault(t *testing.T) {
	path := write(t, "b: []\na: []\n")
	set, err := Load(path, Env{}, Kinds{"a": fakeKind("a"), "b": fakeKind("b")})
	if err != nil {
		t.Fatal(err)
	}
	first, err := set.Default()
	if err != nil {
		t.Fatal(err)
	}
	if first.Issuer() != "b" {
		t.Errorf("default %s", first.Issuer())
	}
}

func TestAPlaceholderExpandsFromTheEnvironment(t *testing.T) {
	t.Setenv("PROVIDERS_TEST_VALUE", "client")
	path := write(t, "a:\n  - client_id: ${PROVIDERS_TEST_VALUE}\n")
	var seen string
	kind := func(node *yaml.Node, _ Env) (Built, error) {
		var entries []struct {
			ClientID string `yaml:"client_id"`
		}
		err := Decode(node, &entries)
		seen = entries[0].ClientID
		return Built{}, err
	}
	if _, err := Load(path, Env{}, Kinds{"a": kind}); err != nil {
		t.Fatal(err)
	}
	if seen != "client" {
		t.Errorf("client_id %q", seen)
	}
}

func TestListingAndLookup(t *testing.T) {
	set := New(nil, fakeClient{issuer: "https://a", kind: "idpd"})
	if _, err := set.Client("https://a"); err != nil {
		t.Error(err)
	}
	if _, err := set.Client("https://b"); err == nil {
		t.Error("an unknown issuer without a federation")
	}
	infos, err := set.Providers()
	if err != nil || len(infos) != 1 || infos[0].Type != "idpd" {
		t.Errorf("%+v, %v", infos, err)
	}
}
