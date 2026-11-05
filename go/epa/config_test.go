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

package epa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validProxy() ProxyConfig {
	return ProxyConfig{
		Name:           "p",
		Env:            EnvRef,
		Timeout:        time.Second,
		VsdmHmacKeyHex: "secret-key-value",
		VsdmHmacKeyID:  "kid",
	}
}

func TestProxyConfigValidateChecksEachSetting(t *testing.T) {
	valid := validProxy()
	if err := valid.Validate(); err != nil {
		t.Fatalf("a valid proxy: %v", err)
	}
	for name, tc := range map[string]struct {
		change func(*ProxyConfig)
		want   string
	}{
		"no name":                  {func(c *ProxyConfig) { c.Name = "" }, "name is required"},
		"a name unfit for a route": {func(c *ProxyConfig) { c.Name = "a/{b}" }, "name may hold only"},
		"no env":                   {func(c *ProxyConfig) { c.Env = "" }, "env must be"},
		"unknown env":              {func(c *ProxyConfig) { c.Env = "staging" }, "env must be"},
		"no timeout":               {func(c *ProxyConfig) { c.Timeout = 0 }, "timeout"},
		"negative timeout":         {func(c *ProxyConfig) { c.Timeout = -time.Second }, "timeout"},
		"unknown vau_cert_verify":  {func(c *ProxyConfig) { c.VAUCertVerify = "sometimes" }, "vau_cert_verify"},
		"no hmac key":              {func(c *ProxyConfig) { c.VsdmHmacKeyHex = "" }, "vsdm_hmac_key_hex"},
		"no hmac key id":           {func(c *ProxyConfig) { c.VsdmHmacKeyID = "" }, "vsdm_hmac_key_id"},
	} {
		t.Run(name, func(t *testing.T) {
			c := validProxy()
			tc.change(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret-key-value") {
				t.Errorf("the key is in the error: %v", err)
			}
		})
	}
	for _, mode := range []string{"", "off", "warn", "enforce"} {
		c := validProxy()
		c.VAUCertVerify = mode
		if err := c.Validate(); err != nil {
			t.Errorf("vau_cert_verify %q: %v", mode, err)
		}
	}
	for _, env := range []Env{EnvDev, EnvTest, EnvRef, EnvProd} {
		c := validProxy()
		c.Env = env
		if err := c.Validate(); err != nil {
			t.Errorf("env %q: %v", env, err)
		}
	}
}

func TestConfigValidateNeedsAValidProxy(t *testing.T) {
	if err := (&Config{}).Validate(); err == nil {
		t.Error("no proxies accepted")
	}
	if err := (&Config{ProxyConfigs: []ProxyConfig{}}).Validate(); err == nil {
		t.Error("an empty list accepted")
	}
	bad := validProxy()
	bad.Name = ""
	err := (&Config{ProxyConfigs: []ProxyConfig{validProxy(), bad}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "proxies[1]: name is required") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadConfigFileValidatesAndSetsTheBaseDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	good := "proxies:\n  - name: p\n    env: ref\n    timeout: 5s\n    vsdm_hmac_key_hex: k\n    vsdm_hmac_key_id: i\n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.ProxyConfigs[0].BaseDir != dir || config.ProxyConfigs[0].Timeout != 5*time.Second {
		t.Errorf("config = %+v", config.ProxyConfigs[0])
	}
	if err := os.WriteFile(path, []byte("proxies:\n  - name: p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path); err == nil || !strings.Contains(err.Error(), "validate config") {
		t.Errorf("err = %v", err)
	}
}

func TestRedactedShowsNoSecretAndLeavesTheConfigAlone(t *testing.T) {
	proxy := validProxy()
	proxy.AuthnP12Password = "p12-password-value"
	config := &Config{ProxyConfigs: []ProxyConfig{proxy}}
	shown := config.Redacted()
	if got := shown.ProxyConfigs[0]; got.VsdmHmacKeyHex != redactedValue || got.AuthnP12Password != redactedValue || got.Name != "p" {
		t.Errorf("shown = %+v", got)
	}
	if config.ProxyConfigs[0].VsdmHmacKeyHex != "secret-key-value" || config.ProxyConfigs[0].AuthnP12Password != "p12-password-value" {
		t.Error("the configuration itself was changed")
	}
}
