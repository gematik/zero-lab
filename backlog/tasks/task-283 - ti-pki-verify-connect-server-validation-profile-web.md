---
id: TASK-283
title: ti pki verify --connect <server> --validation-profile web
status: Done
assignee: []
created_date: '2026-11-10T18:40:00Z'
updated_date: '2026-11-10T19:52:00Z'
labels:
  - rust
  - ti-cli
dependencies:
  - TASK-282
priority: medium
ordinal: 299000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback: no command checks a web server under the web profile; verify --connect validates only against the TI PKI. Add web as a validation profile with --connect: the server's chain checked by ti-tls's web verifier (system roots, the name, revocation), reported like verify's other results with the warnings.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti pki verify --connect HOST --validation-profile web reports the web verdict, the revocation source and warnings; exit 0 valid, 1 refused; web is refused without --connect
- [x] #2 JSON schema, help and AGENTS.md updated; tests against a loopback TLS server with a test root
- [x] #3 With --connect, --validation-profile auto takes a server with a TI certificate type or a TSL CA as issuer to the TI's validation, any other to the web TLS server verdict, and says which and why (text and JSON); without --connect auto stays TI-only
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer's corrections applied: the output is a TLS server's verdict under a TLS profile of spec/pki-validation (ti-client peer::TlsServerVerdict with a TlsProfile field, peer::web_server_verdict; ti-cli verify_tls_server, heading 'TLS server verdict'), in its own schema rust/ti-cli/schemas/pki-verify-tls-server.json (ti schema pki verify tls-server; pki-verify.json unchanged; tests pick the schema by tls_profile). Fields: server, tls_profile, profile_reason, valid, host, at, revocation {source, stapled}, trust, chain, errors/warnings with TLSV codes. Decisions: the handshake is ti-tls's own (client_config, the WebVerifier's signature checks) and judges at --at, not rustls's clock; SNI and name are --fqdn, else HOST; TI-only options (--offline, --issuer, --intermediates, --nist-only, --ocsp-*) are a usage error under web. Auto with --connect: ti when select_for_cert finds a TI certificate type, or the issuer is a CA of the env's TSL (env given or detected); the TSL is the one at hand (cache), never downloaded for the choice, so an internet server does not wait on the TI's download points; without one the reason says so. Tests: tests/verify_tls_server.rs with fixtures tls/web/generate.sh (TEST-ONLY keys committed, valid around 2026-01-01, --at), incl. a TI-typed server that auto keeps with the TI (offline, ref).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti pki verify --connect HOST gives a TLS server verdict under the web profile (system roots or --cacert, name, keys, validity, revocation with its source, warnings); --validation-profile web forces it, auto picks TI for a TI certificate type or a CA of a cached TSL and says why. Its own schema pki-verify-tls-server.json (ti schema pki verify tls-server); pki-verify.json unchanged.
<!-- SECTION:FINAL_SUMMARY:END -->
