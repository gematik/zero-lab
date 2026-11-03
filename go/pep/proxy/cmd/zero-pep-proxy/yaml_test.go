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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/oidf"
)

func TestARelyingPartyFileLoads(t *testing.T) {
	cfg := new(oidf.RelyingPartyConfig)
	if err := loadYAML("../../../../oidf/testdata/relying-party.yaml", cfg); err != nil {
		t.Fatal(err)
	}

	if cfg.Subject != "https://rp.example.com" {
		t.Errorf("sub = %q", cfg.Subject)
	}
	if cfg.FedMasterURL != "https://app-ref.federationmaster.de" {
		t.Errorf("fed_master_url = %q", cfg.FedMasterURL)
	}
	if cfg.RelyingParty.ClientName != "Zero Trust Lab" {
		t.Errorf("client_name = %q", cfg.RelyingParty.ClientName)
	}
	if len(cfg.RelyingParty.RedirectURIs) == 0 {
		t.Error("redirect_uris empty")
	}
	if cfg.SignKey.KeyPEMPath == "" {
		t.Errorf("sign_key.key_pem_path = %q", cfg.SignKey.KeyPEMPath)
	}
	if cfg.ClientKey.CertPEMPath == "" {
		t.Errorf("client_key.cert_pem_path = %q", cfg.ClientKey.CertPEMPath)
	}

	// buildMetadata fills the OIDF boilerplate (response_types, algs, …) the config omits.
}

func TestAnOutdatedProviderKeyStopsTheStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(path, []byte("gemidp:\n  - client_id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProviders(path, "https://pep")
	if err == nil || !strings.Contains(err.Error(), `unknown key "gemidp"`) {
		t.Errorf("err = %v", err)
	}
}

func TestAnUnknownFieldInAProviderEntryStopsTheStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(path, []byte("idpd:\n  - client_id: x\n    trust_bundle: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProviders(path, "https://pep"); err == nil || !strings.Contains(err.Error(), "trust_bundle") {
		t.Errorf("err = %v", err)
	}
}

func TestProviderEntriesKeepTheFilesOrderAndExpandPlaceholders(t *testing.T) {
	t.Setenv("PROVIDERS_TEST_VALUE", "client")
	path := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(path, []byte("b:\n  - client_id: ${PROVIDERS_TEST_VALUE}\na: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := providerEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Key != "b" {
		t.Fatalf("%+v", entries)
	}
	var values []struct {
		ClientID string `yaml:"client_id"`
	}
	if err := entries[0].Decode(&values); err != nil {
		t.Fatal(err)
	}
	if values[0].ClientID != "client" {
		t.Errorf("client_id %q", values[0].ClientID)
	}
}
