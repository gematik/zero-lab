package common

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gematik/zero-lab/go/ti/state"
)

// CLIStateFile is the canonical path of the shared SQLite state store. The
// store is shared by the ePA and PKI command groups; key prefixes (epa:, pki:)
// keep their domains apart, and `ti epa state` / `ti pki state` each manage
// only their own half. Everything in it is TTL'd and re-fetchable, so it lives under
// XDG_STATE_HOME rather than next to the user-authored files in TelematikDir.
func CLIStateFile() string {
	return filepath.Join(TelematikStateDir(), "cli-state.db")
}

// legacyCLIStateFile is where the store lived before it moved out of
// XDG_CONFIG_HOME. Kept for the one-shot migration in [LoadCLIState].
func legacyCLIStateFile() string {
	return filepath.Join(TelematikDir(), "cli-state.db")
}

// LoadCLIState opens the SQLite-backed state store at the canonical path.
// Callers are responsible for Close().
func LoadCLIState() (*state.SQLiteStore, error) {
	path := CLIStateFile()
	migrateCLIState(legacyCLIStateFile(), path)
	s, err := state.OpenSQLite(path)
	if err != nil {
		return nil, fmt.Errorf("opening state file: %w", err)
	}
	return s, nil
}

// migrateCLIState moves a pre-existing store from the legacy path to the
// current one, taking any WAL sidecars along so an unclean shutdown doesn't
// lose the last writes. Best-effort throughout: the store holds nothing but
// caches, so a failed move costs a re-fetch, never a broken command.
func migrateCLIState(from, to string) {
	if from == to {
		return
	}
	if _, err := os.Stat(from); err != nil {
		return
	}
	if _, err := os.Stat(to); err == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		slog.Debug("state: creating state dir failed, keeping legacy store", "dir", filepath.Dir(to), "err", err)
		return
	}
	if err := os.Rename(from, to); err != nil {
		slog.Debug("state: migrating store failed, starting fresh", "from", from, "to", to, "err", err)
		return
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Rename(from+suffix, to+suffix); err != nil && !os.IsNotExist(err) {
			slog.Debug("state: migrating sidecar failed", "file", from+suffix, "err", err)
		}
	}
	slog.Debug("state: migrated store", "from", from, "to", to)
}

// GetJSON reads key from the store and decodes its value into a fresh T. The
// boolean is false on miss (absent or expired).
func GetJSON[T any](s state.Store, key string) (T, bool, error) {
	var zero T
	data, ok, err := s.Get(key)
	if err != nil || !ok {
		return zero, ok, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return zero, false, fmt.Errorf("state: decoding %s: %w", key, err)
	}
	return v, true, nil
}

// SetJSON encodes v and stores it under key.
func SetJSON[T any](s state.Store, key string, v T, opts ...state.SetOption) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("state: encoding %s: %w", key, err)
	}
	return s.Set(key, data, opts...)
}
