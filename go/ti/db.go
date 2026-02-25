package main

import (
	"fmt"

	"github.com/adrg/xdg"
	bolt "go.etcd.io/bbolt"
)

func openDB() (*bolt.DB, error) {
	path, err := xdg.DataFile("telematik/cli.db")
	if err != nil {
		return nil, fmt.Errorf("resolving db path: %w", err)
	}
	return bolt.Open(path, 0o600, nil)
}
