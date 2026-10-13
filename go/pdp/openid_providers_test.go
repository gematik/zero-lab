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

package pdp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOpenidProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openid-providers.yaml")
	yaml := `
oidc:
  - issuer: https://op.example.com
    client_id: cid
    name: Example
gemidp:
  - client_id: gid
    environment: ref
oidf:
  sub: https://rp.example.com
  fed_master_url: https://app-test.federationmaster.de
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	oidcs, gemidps, rp, err := LoadOpenidProviders(path)
	if err != nil {
		t.Fatalf("LoadOpenidProviders: %v", err)
	}
	if len(oidcs) != 1 || oidcs[0].Issuer != "https://op.example.com" {
		t.Errorf("oidc = %+v", oidcs)
	}
	if len(gemidps) != 1 || gemidps[0].ClientID != "gid" {
		t.Errorf("gemidp = %+v", gemidps)
	}
	if rp == nil || rp.Subject != "https://rp.example.com" {
		t.Errorf("oidf = %+v", rp)
	}
}

func TestLoadOpenidProvidersMissingFile(t *testing.T) {
	if _, _, _, err := LoadOpenidProviders(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
