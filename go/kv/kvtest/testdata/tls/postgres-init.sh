#!/bin/sh
# TEST ONLY, for the Postgres with TLS of just kv-postgres-test: a role that may connect only with a client
# certificate of the test CA, before every other rule of pg_hba.conf.
set -eu
psql -v ON_ERROR_STOP=1 -U postgres -c "CREATE ROLE kv_mtls LOGIN SUPERUSER PASSWORD 'test-only'"
sed -i '1i hostssl all kv_mtls all scram-sha-256 clientcert=verify-ca' "$PGDATA/pg_hba.conf"
