---
id: TASK-228
title: 'ti probe: TLS verification is turned off'
status: In Progress
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T11:41:00Z'
labels:
  - ti-cli
  - security
dependencies: []
priority: medium
ordinal: 239000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while planning TASK-97: ti-cli/src/commands/probe.rs disables certificate verification for every probed host, production TI endpoints included. Once TASK-97 (d) exists the probe can verify with the endpoint's profile and report the verdict instead of skipping it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the probe verifies with the endpoint's profile and reports the TLS verdict
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
On spec/pki-validation (with TASK-97):
1. endpoints.json: a tls field per endpoint, ti or web, web by default (internet and catalog instances); epa-1/epa-2 ti in every env. idpd-ti and erx stay web (the IDP-Dienst and E-Rezept present public certificates); a refusal shows it if not.
2. probe.rs: one agent per profile through ti_tls::ureq::agent. web: http::web_config (system roots or --cacert/--capath). ti: the env's TSL and roots loaded once through Session/load_trust, ServerCheck plus OcspChecker over a probe-timed transport; loaded only when an endpoint needs it, a load failure fails those endpoints with its reason instead of aborting.
3. A refused certificate is an answer: status fail, answered true, detail 'TLS <profile>: <reason>'; JSON gains tls {profile, verified}.
4. Tests: endpoint profiles per env; refusal classification; end to end against a local TLS server with a self-signed P-256 fixture (web refuses: unknown issuer). Schema, AGENTS, README, release notes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/pki-validation (012b54c6), with TASK-97. endpoints.json names tls ti for epa-1/epa-2 in every env, web by default. Agents per profile through ti_tls::ureq::agent: web via http::web_config, ti via Session/load_trust, ServerCheck and OcspChecker over a transport limited to 3 s. A refused certificate: status fail, answered true, 'TLS <profile>: <reason>' (ti-tls Refused verdicts by code); JSON tls {profile, verified}, schema extended. Tests: endpoint profiles per env, refusal reasons, end to end against a local self-signed P-256 server (fixture tests/fixtures/tls). Live 2026-11-06: ref and dev epa-1/2 verified under ti with OCSP, idpd-ti and erx verified under web; prod and test TI hosts not routed from here. The catalog is refused under web in every env (RSA-2048): TASK-231.
<!-- SECTION:NOTES:END -->
