---
id: DRAFT-1
title: >-
  Observability specification: metrics by Prometheus, bounded labels, admin
  listener acceptance, health metrics (draft)
status: Draft
assignee: []
created_date: '2026-11-20 16:59'
labels:
  - servers
  - docs
  - observability
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Draft agreed with the maintainer on 2026-11-20 as input for a detailed observability specification, to be written later. Not binding: servers.md is unchanged until that specification exists.

## Findings

- ZETA Guard (zeta-guard-helm, charts/zeta-guard/values.yaml): the telemetry-gateway, an OpenTelemetry collector, scrapes Prometheus from Keycloak (authserver:9000/auth-mgmt/metrics, management port), the PEP's nginx-prometheus-exporter (:9113), OPA (:8181) and nginx-ingress (:9113), in plaintext; job names are load-bearing for the dashboards. Traces and logs go by OTLP; ngx_pep alone also pushes metrics by OTLP. docs/explanations/Telemetry.md says Keycloak's metrics go by OTLP; the chart scrapes them.
- keycloak-zeta disables Quarkus' http-server metrics binder: the HTTP method as an unbounded label grew until OOM (CVE-2026-40984 family).
- Common sidecars all expose Prometheus on a TCP port of their own: SPIRE agent (Workload API on a Unix socket only, metrics on TCP with optional TLS/mTLS and an allowlist of SPIFFE IDs; push via statsd, DogStatsd, M3), Vault Agent (a `metrics_only` listener; TLS by default; metrics need a token unless `unauthenticated_metrics_access`), Istio (:15020/stats/prometheus, plaintext), Linkerd (:4191/metrics), Dapr (:9090), cloud-sql-proxy (`--prometheus`, localhost /metrics). None of them pushes OTLP.
- Dependency: prometheus-client 0.26.0 (2026-11-11; 0.x, frequent breaking releases; forbids unsafe itself) brings 7 new crates, dtoa and the parking_lot family with unsafe. Recommended instead: a hand-written text exposition (std atomics, label sets fixed at start), served over axum/hyper/rustls already in the tree.

## Proposed rule text

**Rule 14, the export sentence replaced:**
Metrics are a Prometheus exposition in the text format, scraped from the admin listener (rule 23) by the deployment's collector, as the ZETA Guard telemetry-gateway scrapes Keycloak, nginx and OPA; traces and logs go by OTLP to the same collector, logs also as JSON to stdout. Code instruments through one small internal interface, so an OTLP exporter for metrics stays a wiring choice at the edge (the command), and the exporter's library falls under the dependency rules. A scrape endpoint is never on the public port.
- **Bounded labels.** A label takes its values from a set fixed at start: an enum of the code (method, outcome, reason) or the configuration (key IDs of the keys file, names of upstreams). A value from a request, a peer or an error message is never a label: whoever chooses label values chooses the server's memory, as an unbounded HTTP method label did in Quarkus' metrics (keycloak-zeta disables that binder). A value outside the set counts as `other`.
- **Names.** Prometheus conventions: `<component>_<what>_<unit>` in base units (seconds, bytes), counters ending in `_total`; one name means one thing in every server.

**Rule 23:**
Admin, metrics, health and debug endpoints listen on their own port with their own authentication (mTLS with an allowlist), restricted by NetworkPolicy, except the bare probe path of rule 31 …
- **A weaker admin listener is the operator's acceptance.** A collector that scrapes without a client certificate, or in plaintext, is admitted only as rule 29 admits plaintext: the operator accepts it with a setting of its own beside the listener's URL, `…_TLS_ACCEPTED=true` for TLS without client authentication on an `https://` listener without a client CA, `…_PLAINTEXT_ACCEPTED=true` for `http://`. Unset, or any other value, such a listener is refused at start; accepted, the acceptance is logged and reported (rule 7). The admin listener then serves metrics and the probe path only, never an administrative operation.

**Rule 31, how the kubelet reaches it, new point:**
- Such a sidecar (Unix socket only) may open one admin listener for metrics (rule 23), as SPIRE's agent and Vault Agent do beside their Unix sockets: metrics only, never the interface, never a probe path. Without it configured, the sidecar opens no TCP port.

**Rule 31, Observable:**
Each change of the health state is one log line with the old state, the new state and the reason, and the state is a metric (rule 14): a gauge `<component>_health_serving` of 1 or 0, a counter `<component>_health_changes_total` and the age of the last background check, `<component>_health_check_age_seconds`, so that a check that stopped running shows as well as a dependency that stopped answering.

**Rule 8, sidecars inside the enclave:** "have no network listener but the metrics listener rule 31 allows".

**naming-and-config:** `…_PLAINTEXT_ACCEPTED` also for a plaintext admin listener (rule 23); new `…_TLS_ACCEPTED`: `true` accepts an admin listener with TLS but without client authentication; unset or any other value, an admin listener without a client CA is refused.
<!-- SECTION:DESCRIPTION:END -->
