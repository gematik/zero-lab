---
id: TASK-394
title: >-
  Servers checked against rule 31: probes per container, liveness apart from
  dependencies, health as a metric
status: To Do
assignee: []
created_date: '2026-11-19 13:42'
labels:
  - servers
  - kubernetes
dependencies:
  - TASK-393
references:
  - docs/design/servers.md
priority: medium
ordinal: 407000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rule 31 (TASK-393) asks for startup, readiness and liveness probes on every container, sidecars included; liveness that does not depend on a dependency; health read from state a background check keeps; the bare probe path on the admin listener or an exec probe for a Unix-socket sidecar; each change of the health state as a log line and a metric. Known gaps at the time of writing, not yet checked in full: metsubushi serves /healthz on its main port and uses it for readiness and liveness alike (go/metsubushi/k8s.yaml); hsm-proxy (ti-hsm-proxy, TASK-389) reports the health state through grpc.health.v1 and hsm-proxy health ready|live, but writes no log line and no metric when it changes. zero-pdp is frozen and is checked when work on it resumes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-pep-proxy, zero-caddy, zero-epa, metsubushi and hsm-proxy are each checked against rule 31, with what conforms and what does not in the notes
- [ ] #2 Each gap is fixed or has a task of its own
<!-- AC:END -->
