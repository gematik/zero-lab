---
id: TASK-136.1
title: Konnektor configuration core with config show and config test (read-only)
status: In Progress
assignee: []
created_date: '2026-10-29T06:44:00Z'
updated_date: '2026-10-29T07:29:00Z'
labels:
  - ti-cli
  - connector
  - security
milestone: m-0
dependencies: []
parent_task_id: TASK-136
priority: medium
ordinal: 165000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First part of TASK-136. A core module (not in ti-cli, so the planned GUI uses it too) with the .kon model, validation, redaction and the test steps with a JSON report; ti-cli's config show and config test as front ends. Decisions in TASK-136's notes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The model, validation, redaction and test steps live in a core (ti-connector-client or a new crate, decided in the plan) under the workspace lints, with no dependency that contains unsafe outside the TASK-156 list
- [x] #2 The .kon parser accepts credentials type none (Credentials::None: no client certificate, no Authorization header); unsupported types still fail
- [x] #3 config show NAME prints the configuration with every secret redacted, text and JSON; a JSON schema describes it
- [x] #4 config test NAME runs file (mode, plain-text secrets), DNS/TCP, TLS with the pin or insecureSkipVerify, client authentication, connector.sds over HTTPS, versions, call context and card list in order, each ok, warn or fail with a hint; a JSON schema describes the report
- [x] #5 test reports insecureSkipVerify and credentials type none as fail for env pu and as warn otherwise; the parser does not refuse them on load
- [x] #6 The call-context errors 4004, 4005, 4006, 4010, 4011, 4021 and 4204 lead to hints naming mandant, client system and workplace
- [x] #7 connector configs and connector use keep working; AGENTS.md and the help describe the new commands
- [x] #8 Tests named after the requirement each proves, against a local Konnektor stub; the new parser parts are covered by the .kon fuzz target (TASK-47)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. ti-connector-client: Credentials::None (parser, authorization, ureq without client auth).
2. Fault hints (4004 ... 4204) from ti-cli/src/error.rs into ti-connector-client; ti-cli uses them from there.
3. Core view with redacted secrets (plain, ${NAME}, absent) and the PKCS#12 client certificate (ti-pkcs12 becomes a regular dependency).
4. Core module check: pure functions from the host's observations (file mode, raw JSON, TCP/TLS, SDS response, GetCards answer) to steps with status ok, warn, fail or skip, a message and a hint; steps after a fail are skipped.
5. ureq feature: probe for DNS, TCP and the TLS handshake with KonnektorVerifier, keeping the server certificate also when the handshake fails.
6. ti-cli: connector config show|test [NAME], schemas connector-config-show.json and connector-config-test.json, exit 1 on a fail; no cache for test; file mode on unix only.
7. Tests per rule; TLS tests for pin, mismatch, insecure, rejected client certificate; ti-cli fake Konnektor over TLS; show leaks no secret.
8. ti-connector-client/fuzz with a target for Dotkon::parse and the raw-secret check (the .kon part of TASK-47).
9. AGENTS.md, help, ReleaseNotes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented (2026-10-29):
- ti-connector-client: Credentials::None and Credentials::kind; config::ConfigView (secrets only as plain/environment/absent, user ID only as set, client certificate via ti-pkcs12, trust store as pin/ca with SHA-256); check (pure steps file, tcp, tls, auth, sds, context, cards; Report skips after a fail); ureq::probe (DNS, TCP, TLS handshake through a recording wrapper around KonnektorVerifier) and ureq::check_config (the driver, SDS and GetCards through the caller's transport, so ti-cli keeps its -v logging); Fault::hint and fault_hint moved from ti-cli, command names in the hints replaced by 'the card list'.
- ti-cli: connector config show|test [NAME], schemas connector-config-show.json and connector-config-test.json, exit 1 on a fail, no cache, -x skips tcp and tls; agent_config/explicit_proxy/Logged::new extracted from connector::open.
- Tests: tests/check.rs (23, one per rule), tests/probe.rs (7, the driver against a loopback TLS Konnektor: pin, changed pin, insecure, client certificate required, mutual TLS, 4021, closed port), ti-cli config_show_carries_no_secret and config_test_fails_an_http_url_and_skips_the_rest. Deviation from the plan: the ti-cli fake Konnektor stays plain HTTP; the TLS paths are covered in ti-connector-client's tests/probe.rs.
- Fuzz: ti-connector-client/fuzz target dotkon (parser, file check, view never shows the password), just fuzz-ti-connector-client; 573k runs in 30 s without a finding.
- just check passes.
- AC1 open: the code is in the core under the workspace lints, but ti-pkcs12 (RustCrypto ciphers) is now a regular dependency of ti-connector-client; whether its tree is within the unsafe list is decided by TASK-156, which has no list yet.
- Open: HITL against a real Konnektor (ti connector config test NAME, ti connector config show NAME).
<!-- SECTION:NOTES:END -->
