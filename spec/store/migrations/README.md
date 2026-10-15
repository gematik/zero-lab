# Migrations

`<n>.sql` takes a database from format level `n − 1` to `n` (README.md, section K). Each file
runs inside the transaction of STORE-103; the implementation checks the level first and sets
`user_version` and `meta` itself, so a file holds only the schema change.

Level 1 is created by `../schema.sql` and has no migration.
