module github.com/gematik/zero-lab/go/sqlitestore

go 1.26.4

// SQLite compiled to Go without cgo, so that CGO_ENABLED=0 builds keep working; the
// approved driver of spec/store's SQLite backend (TASK-103.7, 2026-10-16).
require github.com/ncruces/go-sqlite3 v0.35.6

require github.com/gematik/zero-lab/go/store v0.0.0-20261020122418-c03067b82aaf

require (
	github.com/ncruces/go-sqlite3-wasm/v6 v6.3.35304 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
