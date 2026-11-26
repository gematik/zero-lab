---
id: TASK-441
title: >-
  kv/postgres, kv/mariadb: database connections as every other connection: TLS
  unless plaintext is accepted explicitly
status: In Progress
assignee: []
created_date: '2026-11-26T19:06:00Z'
updated_date: '2026-11-26T19:27:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 450000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decided by the maintainer on 2026-11-26: always uniform with the other connections, plaintext is an opt-in (servers.md rule 29: secure by default, plaintext an explicit acceptance of the operator, one declared trust source per connection and no fallback between sources). Today the two backends differ from that and from each other. kv/postgres passes sslmode on to pgx, whose default is prefer: TLS when the server offers it, plaintext otherwise, without saying so, and allow and prefer are exactly the fallback rule 29 forbids; a DSN without sslmode is the common case (go/kv/docs/hosts.md tells a host to set it). kv/mariadb requires TLS unless the DSN says tls=false, a switch inside the URL. Plan: both backends verify the server's certificate against the system's roots and the host of the DSN by default, take a CA of the deployment's own through WithTLS, and connect in plaintext only with an option the host sets from a setting of its own beside the DSN (WithPlaintextAccepted, for the host's …_PLAINTEXT_ACCEPTED=true), which the backend logs at Open. The DSN carries no TLS switch: sslmode, sslrootcert and the like in a Postgres DSN and tls in a MariaDB DSN are refused, so that nothing in the address can weaken the connection or disagree with the option. The same for OpenBus and OpenDB. Breaking for hosts: a DSN with sslmode=disable or tls=false no longer starts; the hosts here (zero-pdp, zero-pep-proxy, zaddy) need the acceptance in their configuration, as their listeners have it. The TLS profile (version, curves, suites) is the constants gemSpec_Krypt asks for, as for the other peers, where the drivers allow it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Without an option both backends connect with TLS and verify the server's certificate and name; a server without TLS, with a certificate of another name or of an unknown CA is refused, shown by tests against a database with TLS
- [x] #2 Plaintext only with WithPlaintextAccepted, logged at Open; a DSN that names sslmode, tls or another TLS parameter is refused
- [x] #3 WithTLS takes a CA of the deployment's own in both backends, and a client certificate for mTLS
- [x] #4 OpenBus and OpenDB follow the same rule
- [x] #5 zero-pdp, zero-pep-proxy and zaddy take the acceptance from a setting beside their database URL and refuse plaintext without it; docs, compose files and the e2e guide follow
- [x] #6 go/kv/docs/hosts.md and the release notes say what a host changes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-26, on feat/kv-db-tls. Both backends: TLS with the server's certificate verified for the host of the DSN under the system's roots; WithTLS for a CA, another name or a client certificate (a configuration that skips verification is refused); WithPlaintextAccepted as the one way to plaintext, logged at Open; the DSN carries no transport parameter (Postgres refuses ssl…, gssencmode, channel_binding; MariaDB refuses every parameter, tls=false is gone); pgx's fallback configurations are dropped and PGSSLMODE has no effect (tested with it set to disable, prefer, allow). OpenDB and OpenBus take the two options. Tests against real databases with a TEST-ONLY CA made per run (kv/kvtest/testdata/tls/tlscerts.go; just kv-postgres-test, new, and just kv-mariadb-test): a database without TLS refused by default and opened with the acceptance; with TLS, opened with the CA and the certificate's name, refused under the system's roots, with the address as the name, with another name and with another CA; a role that needs a client certificate refused without and let in with one; the follower's own connection and the bus work over TLS. Hosts: zero-pep-proxy PEP_DATABASE_PLAINTEXT_ACCEPTED and PEP_DATABASE_TLS_CA_PATH; zaddy revocations_database_plaintext_accepted and revocations_database_tls_ca_path; zero-pdp (frozen) DATABASE_PLAINTEXT_ACCEPTED only. Examples, compose file, CONFIG.md, DOCKERHUB.md, zaddy's README, go/kv/docs/hosts.md and the release notes follow. just lint golangci modernize exits 0; the full check and the release are still to come. Raised by the maintainer on the way: zaddy should not have a database at all (see the task to come).
<!-- SECTION:NOTES:END -->
