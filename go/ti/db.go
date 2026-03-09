package main

import (
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// xdgConfigHome returns $XDG_CONFIG_HOME if set, otherwise ~/.config.
// This deliberately ignores platform-specific overrides (e.g. macOS
// ~/Library/Application Support) so the path is consistent everywhere.
func xdgConfigHome() string {
	if h := os.Getenv("XDG_CONFIG_HOME"); h != "" {
		return h
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}

func openDB() (*bolt.DB, error) {
	dir := filepath.Join(xdgConfigHome(), "telematik")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating config directory: %w", err)
	}

	return bolt.Open(filepath.Join(dir, "cli.db"), 0o600, nil)
}
