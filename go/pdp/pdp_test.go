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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/oidftest"
)

func TestLoadConfigFileMergesProviders(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openid-providers.yaml"), []byte(
		"oidc:\n  - issuer: https://op.example.com\n    client_id: cid\n"), 0o600); err != nil {
		t.Fatalf("write providers file: %v", err)
	}
	cfgPath := filepath.Join(dir, "pdp.yaml")
	if err := os.WriteFile(cfgPath, []byte("authorization_server:\n  issuer: https://as.example.com\n"), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadConfigFile(cfgPath, "")
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg.ProvidersPath != filepath.Join(dir, "openid-providers.yaml") {
		t.Errorf("providers path %q", cfg.ProvidersPath)
	}
}

func TestLoadConfigFileRefusesAnOutdatedKey(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "pdp.yaml")
	if err := os.WriteFile(cfgPath, []byte("authorization_server:\n  issuer: https://as.example\n  gematik_idp: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(cfgPath, ""); err == nil {
		t.Error("an outdated key")
	}
}

func TestTheE2EConfigHasOnlyKnownKeys(t *testing.T) {
	if _, err := LoadConfigFile(filepath.Join("e2e", "testdata", "pdp.e2e.yaml"), ""); err != nil {
		t.Error(err)
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// TestTheProvidersFileHandsItsKeyFilesToTheProgramsLoader proves that pdp reads no key file either: the oidf entry's
// key files, resolved against the providers file's directory, go to the loader the program supplies, and the relying
// party built with its keys goes to the authorization server.
func TestTheProvidersFileHandsItsKeyFilesToTheProgramsLoader(t *testing.T) {
	federation := oidftest.New(t)
	anchor, err := json.Marshal(federation.TrustAnchor().Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "openid-providers.yaml")
	content := fmt.Sprintf(`oidf:
  entity: https://rp.example
  master: %s
  master_jwk_path: secrets/master.jwk
  sign_key: { key_pem_path: secrets/sign.pem, kid: sign }
  enc_key: { key_pem_path: secrets/enc.pem, kid: enc }
  client_key: { key_pem_path: /etc/rp/client.pem, cert_pem_path: secrets/client-cert.pem, kid: client }
  relying_party:
    client_name: rp
    organization_name: Example
    redirect_uris: [https://rp.example/cb]
    keywords: ["product_type:example", "product_type_version:0.0.0"]
    contacts: [support@example.invalid]
    ti_features_supported: { id_token_version_supported: ["1.0.0"] }
  federation_entity:
    name: rp
`, federation.MasterURL())
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var got oidf.KeyFiles
	loader := func(files oidf.KeyFiles) (oidf.Keys, error) {
		got = files
		agreement, err := newKey(t).ECDH()
		if err != nil {
			return oidf.Keys{}, err
		}
		// The master's key is the loader's to read too: its file is named beside the others.
		master, err := oidf.NewJwkFromJSON(string(anchor))
		if err != nil {
			return oidf.Keys{}, err
		}
		return oidf.Keys{Sign: newKey(t), Decrypt: agreement, Client: selfSigned(t), Master: master}, nil
	}
	config := &Config{ProvidersPath: path, OIDFKeys: loader, OIDFDocuments: oidf.NewMemoryDocuments(16, nil), HTTPClient: federation.Client()}
	if err := loadProviders(config); err != nil {
		t.Fatal(err)
	}
	want := oidf.KeyFiles{
		SignKey:       oidf.KeyFile{KeyPEMPath: filepath.Join(dir, "secrets/sign.pem"), Kid: "sign"},
		EncKey:        oidf.KeyFile{KeyPEMPath: filepath.Join(dir, "secrets/enc.pem"), Kid: "enc"},
		ClientKey:     oidf.KeyFile{KeyPEMPath: "/etc/rp/client.pem", CertPEMPath: filepath.Join(dir, "secrets/client-cert.pem"), Kid: "client"},
		MasterJWKPath: filepath.Join(dir, "secrets/master.jwk"),
	}
	if got != want {
		t.Errorf("the loader got %+v, want %+v", got, want)
	}
	if config.AuthzServerConfig.RelyingParty == nil || config.AuthzServerConfig.Providers.Federation() != config.AuthzServerConfig.RelyingParty {
		t.Error("the relying party did not reach the authorization server")
	}
}

// Keys rule 1: without a loader from the program, an oidf entry has no keys and stops the start.
func TestKeysRule1_AnOIDFEntryWithoutTheProgramsLoaderStopsTheStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openid-providers.yaml")
	if err := os.WriteFile(path, []byte("oidf:\n  entity: https://rp.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadProviders(&Config{ProvidersPath: path, OIDFDocuments: oidf.NewMemoryDocuments(16, nil)}); err == nil || !strings.Contains(err.Error(), "loader") {
		t.Errorf("err = %v", err)
	}
}
