package common

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateCLIState(t *testing.T) {
	t.Run("moves store and sidecars", func(t *testing.T) {
		dir := t.TempDir()
		from := filepath.Join(dir, "config", "cli-state.db")
		to := filepath.Join(dir, "state", "cli-state.db")
		if err := os.MkdirAll(filepath.Dir(from), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{"", "-wal"} {
			if err := os.WriteFile(from+suffix, []byte("payload"+suffix), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		migrateCLIState(from, to)

		for _, suffix := range []string{"", "-wal"} {
			got, err := os.ReadFile(to + suffix)
			if err != nil {
				t.Fatalf("reading migrated %q: %v", to+suffix, err)
			}
			if string(got) != "payload"+suffix {
				t.Errorf("migrated %q = %q", to+suffix, got)
			}
			if _, err := os.Stat(from + suffix); !os.IsNotExist(err) {
				t.Errorf("legacy %q still present", from+suffix)
			}
		}
	})

	t.Run("keeps existing target", func(t *testing.T) {
		dir := t.TempDir()
		from := filepath.Join(dir, "config", "cli-state.db")
		to := filepath.Join(dir, "state", "cli-state.db")
		for _, p := range []string{from, to} {
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(from, []byte("legacy"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, []byte("current"), 0o600); err != nil {
			t.Fatal(err)
		}

		migrateCLIState(from, to)

		got, err := os.ReadFile(to)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "current" {
			t.Errorf("target overwritten: %q", got)
		}
	})

	t.Run("no legacy store is a no-op", func(t *testing.T) {
		dir := t.TempDir()
		to := filepath.Join(dir, "state", "cli-state.db")
		migrateCLIState(filepath.Join(dir, "config", "cli-state.db"), to)
		if _, err := os.Stat(filepath.Dir(to)); !os.IsNotExist(err) {
			t.Error("state dir created without a store to migrate")
		}
	})
}

func TestCLIStateFileUsesStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/state-home")
	if got, want := CLIStateFile(), "/tmp/state-home/telematik/cli-state.db"; got != want {
		t.Errorf("CLIStateFile() = %q, want %q", got, want)
	}
}
