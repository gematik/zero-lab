---
id: DRAFT-1
title: >-
  Observability specification: metrics by Prometheus, bounded labels, admin
  listener acceptance, health metrics (draft)
status: Draft
assignee: []
created_date: '2026-11-20 16:59'
updated_date: '2026-11-22 17:02'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, gemSpec_ZETA 1.3.2 (release; draft 2.0.0_CC unchanged on these points) checked for telemetry:
- Signals: every ZETA Guard component except the databases produces OpenTelemetry-conformant traces, metrics and logs (A_27264). HTTP proxy, authorization server, policy engine and notification service send traces of every operation to the cluster's telemetry data service (A_27492-02). That service forwards by OTLP over gRPC or HTTP/JSON (A_27261), traces to gematik in batches, asynchronously (A_27727-01), and must keep that delivery working (A_27796).
- Security monitoring to the TI-SIEM, through the telemetry service: per request, PEP and PDP send a fixed set of attributes as part of an OTel trace, named after OTel semantic conventions (client.address, user_agent.original, http.request.method, http.route, ...; A_28783); every detected attack as part of a trace (A_28795-01); the PDP's policy decision as an OTel log (A_28867); once a day security KPIs as an OTel metric (A_25484-03: attempts by unregistered clients, botnet hits, accesses per country split into insured and professionals, failed client activations); all of it linked by one correlation ID through the request (A_28796).
- Privacy: no medical data, no security-relevant data (keys, tokens) and nothing suited to profiling in logging and monitoring (A_25744, A_25745, A_25746, A_27260), the HSM proxy likewise (A_28822); security telemetry not passed on and deleted on time (A_28960, A_28964).
- Shared Signals: described in chapter 4.7.2 (the monitoring ends a client's session), but explicitly not supported by ZETA for now, as SIEMs and infrastructure lack support.
- Not in the specification: health checks (no requirement), Prometheus (not named; ZETA Guard's chart scrapes Prometheus endpoints into its OTel collector, which turns them into OTel metrics, so a Prometheus exposition meets A_27264 through the collector).

Maintainer's direction for the specification (2026-11-22):
1. Health checks that work alike under Kubernetes, Docker and compose: an exec subcommand of the binary (<binary> health ready|live) serves all three (Kubernetes exec probes, Dockerfile HEALTHCHECK CMD, compose healthcheck test), with no shell in the image; an HTTP probe path on the admin listener where a server has one (rule 31).
2. Metrics as a Prometheus exposition on the admin listener (as already drafted above); the collector converts them for ZETA.
3. Telemetry data, above all security events: traces and logs by OTLP push to the collector (the dependency to be decided: OpenTelemetry Go SDK or a small OTLP exporter of our own), security events as their own signal with the attributes of A_28783/A_28795-01/A_28867 and the correlation ID of A_28796, designed so that a Shared Signals (SSF/CAEP) transmitter can be added later without changing the producers.
<!-- SECTION:NOTES:END -->
