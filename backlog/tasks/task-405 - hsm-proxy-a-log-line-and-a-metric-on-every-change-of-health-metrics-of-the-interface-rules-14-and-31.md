---
id: TASK-405
title: >-
  hsm-proxy: a log line and a metric on every change of health, metrics of the
  interface (rules 14 and 31)
status: To Do
assignee: []
created_date: '2026-11-20 16:05'
updated_date: '2026-11-20 16:59'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ZETA Guard as of 2026-11-20 (keycloak-zeta abb8cef1, zeta-guard-helm main):
- Metrics are Prometheus, scraped by the telemetry-gateway (an OpenTelemetry collector, prometheus receiver, static scrape_configs in charts/zeta-guard/values.yaml): Keycloak on its management port authserver:9000/auth-mgmt/metrics (Quarkus Micrometer, KC_METRICS_ENABLED), the PEP's nginx-prometheus-exporter on pep-proxy-svc:9113, OPA on :8181, nginx-ingress on :9113. The job names are load-bearing for the shipped dashboards.
- Traces and logs go by OTLP push to the gateway (KC_TRACING_ENABLED, KC_TELEMETRY_LOGS_ENABLED); ngx_pep alone pushes its metrics by OTLP as well (one gRPC endpoint, OTEL_EXPORTER_OTLP_ENDPOINT). docs/explanations/Telemetry.md says Keycloak's metrics go by OTLP; the chart scrapes them.
- Lesson from keycloak-zeta (quarkus.properties, CVE-2026-40984 family): Quarkus' http-server binder took the HTTP method as an unbounded label and grew without limit until OOM; it is disabled. Every label here must be bounded: key_id only from the keys file, method and codes from closed enums, never a value from the request.
Recommendation: Prometheus exposition on a management listener apart from the interface, like Keycloak's port 9000, so the gateway scrapes it with one more job; OTLP push is not needed for metrics.

Blocked on the detailed observability specification (maintainer, 2026-11-20); the drafted rules and the dependency evaluation are in DRAFT-1.
<!-- SECTION:NOTES:END -->
