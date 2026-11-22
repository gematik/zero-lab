---
id: TASK-401
title: >-
  hsm-proxy: a TCP listener, own TLS/mTLS or http:// once the operator accepts
  plaintext (rule 29)
status: Done
assignee: []
created_date: '2026-11-19 15:20'
updated_date: '2026-11-22 11:08'
labels:
  - rust
  - hsm
  - transport
dependencies:
  - TASK-399
  - TASK-389
references:
  - rust/ti-hsm-proxy
  - docs/design/servers.md
priority: medium
ordinal: 414000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The sidecar listens on a Unix socket only (HSM_PROXY_LISTEN_URL unix://). Inside the cluster, rule 29 (TASK-399) allows two modes: https:// with the sidecar's own TLS from HSM_PROXY_LISTEN_TLS_CERT_PATH, _KEY_PATH and, for mTLS, _CA_PATH with an allowlist _PEER_NAME; or http:// (h2c) with HSM_PROXY_LISTEN_MESH naming the mesh, refused without it. TLS material is read at start (rule 8); the profile follows gemSpec_Krypt as constants; start-up refuses a key that does not match its certificate, an invalid certificate and an empty CA bundle (rule 17). Needs the maintainer's approval of tokio-rustls (tonic's tls-ring feature), the one new crate; rustls, ring and webpki are in the workspace through ti-tls. Open: A_28830, access by calling component and key_id, which over mTLS can come from the client certificate's identity; over a mesh only from the mesh's policy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 HSM_PROXY_LISTEN_URL takes https:// with own TLS or mTLS, and http:// only with HSM_PROXY_LISTEN_MESH; each mode is logged and reported at start
- [x] #2 Tests over TCP: a client without a certificate, with one outside the allowlist, and with an expired one is refused under mTLS; plaintext without a declared mesh does not start
- [x] #3 It is recorded whether A_28830 is met per mode, or the gap is a task of its own
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19, built on feat/hsm-proxy-tcp, not committed (the maintainer wants to see its size first). Structure at the maintainer's question: src/transport/mod.rs (Listener: Unix, Tls, Mesh; binding, the Unix socket helpers, the health socket), src/transport/tls.rs (profile = ti-tls's TLSV-010 to 012, checks at start per rule 17, acceptor on tokio-rustls with a handshake timeout, client identity from the certificate's SAN DNS names and URIs), src/transport/grpc.rs (tonic, an interceptor holding every interface call to the allowlist over mTLS, grpc.health.v1 without a client certificate, tonic's Connected for the TLS connection). Features: transport (tokio, rustls, tokio-rustls), grpc = transport + tonic; a later jsonrpc takes transport alone. Config: HSM_PROXY_LISTEN_URL unix:// | https:// | http://, HSM_PROXY_LISTEN_TLS_CERT_PATH, _KEY_PATH, _CA_PATH, _PEER_NAME, HSM_PROXY_LISTEN_MESH; inconsistent combinations refused. On TCP the sidecar serves grpc.health.v1 alone on $TMPDIR/hsm-proxy-health.sock for hsm-proxy health. Tests: tests/tls_listener.rs (rule 17 refusals, the profile equal to ti-tls's), tests/tcp_softhsm2.rs (mTLS admits the allowlist, refuses another identity, no certificate and an expired one, health without a certificate; mesh plaintext; the health socket), config tests; certificates and keys made in the test (tests/support/pki.rs, x509-cert's builder; no new crate). 25 tests against SoftHSM2 pass; just check-changed green; tokio-rustls exempted in vet with a note. A_28830: Unix socket, no caller check, the configured keys; mTLS, the listener's allowlist for every key; mesh, the mesh's policy. Per key_id is TASK-402.

2026-11-20 (f4bf9298): HSM_PROXY_LISTEN_MESH became HSM_PROXY_LISTEN_PLAINTEXT_ACCEPTED=true (exact value; empty, 'false' or 'yes' refused; refused beside unix:// and https://). The criteria below read 'declared mesh' as decided on 2026-11-19.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
HSM_PROXY_LISTEN_URL takes unix://, https:// with the sidecar's own TLS or mTLS (allowlist of SAN identities, grpc.health.v1 without a client certificate), and http:// (h2c) only with HSM_PROXY_LISTEN_PLAINTEXT_ACCEPTED=true; each mode is logged at start, with a health socket for the exec probes on TCP. tests/tcp_softhsm2.rs proves the allowlist (stranger, anonymous and expired refused) and plaintext once accepted; config tests prove the refusals. Proven against ngx_pep's released ossl_hsm over mTLS and accepted plaintext (TASK-389). A_28830 per key_id beyond the allowlist stays open in TASK-389; the Java clients' plaintext is TASK-404.
<!-- SECTION:FINAL_SUMMARY:END -->
