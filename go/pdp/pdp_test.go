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

func TestLoadConfigFileMergesProviders(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "openid-providers.yaml"), []byte(
		"oidc:\n  - issuer: https://op.example.com\n    client_id: cid\n"), 0o600)
	cfgPath := filepath.Join(dir, "pdp.yaml")
	os.WriteFile(cfgPath, []byte("authorization_server:\n  issuer: https://as.example.com\n"), 0o600)

	cfg, err := LoadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if len(cfg.AuthzServerConfig.OidcProviders) != 1 ||
		cfg.AuthzServerConfig.OidcProviders[0].Issuer != "https://op.example.com" {
		t.Errorf("providers not merged: %+v", cfg.AuthzServerConfig.OidcProviders)
	}
}
