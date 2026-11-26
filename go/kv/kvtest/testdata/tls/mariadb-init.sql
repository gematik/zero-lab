-- TEST ONLY, for the MariaDB with TLS of just kv-mariadb-test: a user that may connect only with a client
-- certificate of the test CA.
CREATE USER 'kv_mtls'@'%' IDENTIFIED BY 'test-only' REQUIRE X509;
GRANT ALL PRIVILEGES ON *.* TO 'kv_mtls'@'%' WITH GRANT OPTION;
