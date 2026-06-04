package main

import (
	"os"
	"path/filepath"
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
