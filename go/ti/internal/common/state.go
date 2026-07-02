package common

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/gematik/zero-lab/go/ti/state"
)

// CLIStateFile is the canonical path of the shared SQLite state store. The
// store is shared by ePA and PKI caches; key prefixes (epa:, pki:) keep their
// domains apart.
func CLIStateFile() string {
	return filepath.Join(TelematikDir(), "cli-state.db")
}

// LoadCLIState opens the SQLite-backed state store at the canonical path.
// Callers are responsible for Close().
func LoadCLIState() (*state.SQLiteStore, error) {
	s, err := state.OpenSQLite(CLIStateFile())
	if err != nil {
		return nil, fmt.Errorf("opening state file: %w", err)
	}
	return s, nil
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
