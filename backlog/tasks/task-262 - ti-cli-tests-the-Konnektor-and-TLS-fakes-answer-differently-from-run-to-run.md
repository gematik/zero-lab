---
id: TASK-262
title: 'ti-cli tests: the Konnektor and TLS fakes answer differently from run to run'
status: To Do
assignee: []
created_date: '2026-11-08T06:34:00Z'
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
- [ ] #1 both tests pass on 50 consecutive runs
<!-- AC:END -->
