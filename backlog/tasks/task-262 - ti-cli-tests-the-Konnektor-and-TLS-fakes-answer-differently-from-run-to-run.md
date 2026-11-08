---
id: TASK-262
title: 'ti-cli tests: the Konnektor and TLS fakes answer differently from run to run'
status: Done
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-08T10:54:00Z'
labels:
  - rust
  - testing
dependencies: []
ordinal: 278000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Konnektor fake that requires a client certificate (a_konnektor_that_requires_a_client_certificate_refuses_basic, config-new-tested) fails now and then, and a TLS fake's reset message differs between runs. Found during TASK-249/250. A gated or integration test that varies is no proof; make the fakes deterministic.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 both tests pass on 50 consecutive runs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Cause: under TLS 1.3 the Konnektor's refusal of the client follows the handshake; the auth step saw it only with the first request, where a reset could swallow it. The TLS probe now reads the server's first record after the handshake (alert = refused; ticket or 500 ms silence = accepted). The handshake-only ti-cli fake now takes the request and closes with close_notify. konnektor_check: 50/50 stress runs (before: 2 of 60 failed); the ti-cli fake tests 50/50; the tested config-new message identical in 25/25 runs.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Under TLS 1.3 the Konnektor's refusal of the client follows the handshake; the config test now reads the server's first record after it (alert = refused, ticket or 500 ms silence = accepted), so a refusal is no longer lost to a reset. The handshake-only ti-cli fake takes the request and closes with close_notify. Both tests pass 50 of 50 runs.
<!-- SECTION:FINAL_SUMMARY:END -->
