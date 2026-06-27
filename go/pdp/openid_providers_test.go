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
