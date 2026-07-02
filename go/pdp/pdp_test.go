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
