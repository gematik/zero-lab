---
id: TASK-128
title: >-
  Rust: retrofit HTTP fetching to spec/http-cache (cache policy, retries,
  per-origin rest)
status: To Do
assignee: []
created_date: '2026-10-21 07:18'
labels:
  - rust
  - spec
  - ti-pki
  - ti-idpd
dependencies:
  - TASK-125
priority: medium
ordinal: 139000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Once spec/http-cache (TASK-125) states the cache and retry policy, bring the Rust side onto it. Today: ti_store::Cache has max_age, validators and stale_if_error but no shared vectors; ti-pki's load::HttpLoader and Reloader fetch roots.json and the TSL without a general retry policy; only the OcspChecker repeats status errors and rests a responder (OCSP_STATUS_RETRIES, OCSP_STATUS_PAUSE, gemSpec_PKI via C_12791), with its own parameters; ti-idpd and ti-directory send their requests (discovery, PuK_IDP_SIG/ENC, token endpoints) through their own Transport without caching or retries; ti-cli's ureq transports set timeouts only. Retrofit: ti_store::Cache passes the spec's vectors; one retry and per-origin rest implementation used by the loaders, the OCSP checker (with its spec-prescribed parameters as one configuration of it) and the hosts' transports; cacheable documents of ti-idpd (discovery document, IDP keys) go through the cache within the IDP's own validity rules; non-idempotent requests (challenge answer, token exchange) are never retried. Fits TASK-64 (one HTTP vocabulary, ti-http): decide there whether the retry layer lives in that crate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti_store::Cache and the Rust retry layer pass spec/http-cache's vectors; the OCSP checker's repetitions and rest are a configuration of the shared layer with unchanged gemSpec behaviour
- [ ] #2 roots.json, TSL, OCSP and the IDP-Dienst's discovery document and keys are fetched through it; challenge answers and token requests are not retried
- [ ] #3 ti-cli's transports report attempts and resting origins in -v output
<!-- AC:END -->
