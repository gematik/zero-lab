---
id: TASK-405
title: >-
  hsm-proxy: a log line and a metric on every change of health, metrics of the
  interface (rules 14 and 31)
status: To Do
assignee: []
created_date: '2026-11-20 16:05'
labels:
  - servers
  - hsm-proxy
  - observability
dependencies:
  - TASK-389
references:
  - docs/design/servers.md
priority: medium
ordinal: 418000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rule 31 asks that each change of the health state be a log line and a metric; rule 14 asks every server for metrics (rate, errors and duration per endpoint and per dependency, saturation, key-service errors as security signals), exported through one small internal interface, the exporter chosen at the edge, a scrape endpoint only on an admin listener. ti-hsm-proxy (TASK-389) keeps its health in a background check every HSM_PROXY_HEALTH_INTERVAL_MS and reports it through grpc.health.v1 (on the Unix socket of the exec probes, and on a TCP listener) and HealthCheck, but writes nothing when it changes and has no metrics. Outside Kubernetes (systemd, docker) a loss of the HSM is therefore seen only by asking. Found while checking rule 31 (TASK-394).

Metrics need a dependency (prometheus-client, opentelemetry or a hand-written exposition): ask the maintainer with reason, transitive cost, unsafe and unit before choosing. The admin listener for a scrape endpoint is new for the sidecar: decide whether it is one (then rule 23: own port, NetworkPolicy, authentication) or whether OTLP push alone suffices.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each change of the health state (SERVING ↔ NOT_SERVING, first state after start) is one structured JSON log line on stdout with the old and new state and the reason, without key material, PINs or the data signed
- [ ] #2 The health state is a metric (gauge), as are calls per method and key_id, errors per gRPC code and PKCS#11 return value, duration per method, sessions in use and waiting (saturation), and session recoveries
- [ ] #3 Metrics go through one small internal interface; the exporter (OTLP, Prometheus or both) is chosen in main, and the dependency is approved before it is added
- [ ] #4 A scrape endpoint, if any, is on an admin listener apart from the interface, never on the listener of HsmProxyService (rules 14 and 23)
- [ ] #5 Tests named after the rules prove the log line on a change (token lost and back) and the metrics' values on the software token
- [ ] #6 README (Health in a pod, Not here yet) and ReleaseNotes updated; TASK-394 notes point here
<!-- AC:END -->
