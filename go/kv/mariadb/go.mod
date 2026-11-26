module github.com/gematik/zero-lab/go/kv/mariadb

go 1.27.0

require (
	github.com/gematik/zero-lab/go/kv v0.11.1-0.20261126184440-b50a17395e04
	// The MariaDB wire protocol, which the standard library does not speak (design.md, Dependencies).
	// Pure Go, no cgo, no unsafe; it requires filippo.io/edwards25519 alone, for the client_ed25519
	// authentication plugin. Approved by the maintainer on 2026-11-25 (TASK-429).
	github.com/go-sql-driver/mysql v1.10.2
)

require filippo.io/edwards25519 v1.2.0 // indirect
