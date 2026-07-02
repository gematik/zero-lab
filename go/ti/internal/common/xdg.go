package common

import (
	"os"
	"path/filepath"
)

// XDGConfigHome returns $XDG_CONFIG_HOME if set, otherwise ~/.config.
// This deliberately ignores platform-specific overrides (e.g. macOS
// ~/Library/Application Support) so the path is consistent everywhere.
func XDGConfigHome() string {
	if h := os.Getenv("XDG_CONFIG_HOME"); h != "" {
		return h
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}

// TelematikDir returns $XDG_CONFIG_HOME/telematik — the shared TI config root.
// CLI-owned files in this directory carry a `cli-` prefix so they don't
// collide with files written by other TI tools that share this directory.
func TelematikDir() string {
	return filepath.Join(XDGConfigHome(), "telematik")
}
