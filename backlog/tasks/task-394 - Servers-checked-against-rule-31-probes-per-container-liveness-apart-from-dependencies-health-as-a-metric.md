---
id: TASK-394
title: >-
  Servers checked against rule 31: probes per container, liveness apart from
  dependencies, health as a metric
status: Done
assignee: []
created_date: '2026-11-19 13:42'
updated_date: '2026-11-22 18:13'
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
- [x] #1 zero-pep-proxy, zero-caddy, zero-epa, metsubushi and hsm-proxy are each checked against rule 31, with what conforms and what does not in the notes
- [x] #2 Each gap is fixed or has a task of its own
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
hsm-proxy: the missing log line and metric on a change of health, and the interface's metrics, are TASK-405.

2026-11-22, checked against rule 31 (main at 17cd4350, zero-lab-k8s main):
- zero-pep-proxy: no health endpoint and no admin listener at all; the chart (zero-lab-k8s pep/templates/deployment.yaml) has a tcpSocket readiness probe only, no startup and no liveness probe. Readiness would follow its dependencies: the kv store (Postgres) and, since TASK-313, the revocations' freshness (kv/revoked's ErrStale after 90 s). No background check, no log line or metric on a change of health.
- zero-caddy (zaddy): no health of its own; Caddy's admin API on localhost:2019 answers liveness at most; readiness would follow zaddy's dependencies (the revocations it follows, its JWKS file loaded at start). The chart (proxy) has no probes.
- zero-epa: no health endpoint; not for production (maintainer, TASK-362), so not to be fixed.
- metsubushi: /healthz on its main port answers always 200 and serves readiness and liveness alike (go/metsubushi/k8s.yaml); a smoke-test echo server without dependencies, so readiness and liveness are rightly the same; the probe path on the main port is a deviation from the admin listener of rule 23, acceptable for a test tool.
- hsm-proxy: startup, readiness and liveness as exec probes over the Unix socket, health from a background check (TASK-389); the log line and metric on a change are TASK-405.
AC #2 left open: the gaps of zero-pep-proxy and zaddy need tasks of their own, which the maintainer asked not to create yet (2026-11-22).

2026-11-22, maintainer: the gaps of zero-pep-proxy and zaddy (health endpoints, probes, readiness by dependencies) are due in DRAFT-1, the observability specification, and become its tasks.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy, zero-caddy, zero-epa, metsubushi and hsm-proxy checked against servers.md rule 31 (notes). Gaps: zero-pep-proxy and zaddy lack health endpoints, probes and readiness by their dependencies; they are carried by DRAFT-1 (health on the data port unless one of four reasons, /livez and /readyz, <binary> health). zero-epa is not for production; metsubushi conforms for a test tool; hsm-proxy conforms, its log line and metrics are TASK-405.
<!-- SECTION:FINAL_SUMMARY:END -->
