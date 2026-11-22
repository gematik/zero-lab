---
id: TASK-395
title: >-
  servers.md: read at start, changed by a rollout; run-time refresh only for the
  TI's trust material
status: Done
assignee: []
created_date: '2026-11-19 13:53'
updated_date: '2026-11-22 11:08'
labels:
  - docs
  - servers
  - kubernetes
dependencies: []
references:
  - docs/design/servers.md
priority: medium
ordinal: 408000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The rules ask for reload in general: rule 8 'configuration reloads from mounted files', rule 6 'rotation works without a restart of the workload or its sidecars', rule 29 'certificate, key and CA bundle are re-read on change'. In-process reload is code in the TCB, and it makes the configuration reported and attested at start (rule 7) differ from what runs. Maintainer, 2026-11-19: reload is no general rule. Default: read at start, changed by a rollout; run-time refresh is a named exception for material whose validity is shorter than a deployment cycle, which is the TI's verification data (TSL and TI roots, OCSP, federation statements and JWKS, IdP discovery). Infrastructure transport (listener and peer certificates, CA bundles, allowlists), configuration and keys are fixed for a process's life. Documentation only; go/kv's file following is TASK of its own.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Rule 8 says that configuration, TLS material and keys are read at start and changed by a rollout, and lists the material refreshed at run time with the conditions for it (verified before use, atomic swap, old snapshot kept on failure, age as a metric)
- [x] #2 Rules 6, 26 and 29 no longer ask for reload without restart: keys rotate with an overlap by rollouts, TLS material is read at start with expiry as a metric and in readiness, rotation is tested as a rollout
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: rule 8 has 'read at start, changed by a rollout' and 'refreshed at run time: the TI's trust material, and nothing else' (TSL and TI roots, OCSP, federation statements and JWKS, IdP discovery; verified before use, replaced as a whole, old set kept on failure, age as a metric, outside the request path); rule 6 keys rotate with an overlap by rollouts; rule 26 rotation by rollout; rule 29 TLS material read at start, a mismatching or invalid pair refuses the start, expiry a metric and in readiness. Checked in code (2026-11-19): the only run-time reload outside the list is go/kv's file following (TASK-396); go/tipki bundlefile and fetch, ti-pki's Reloader and zero-pep-proxy's revocation reconciliation are on the list or are security state; no TLS reload exists anywhere. TASK-383 (rules 29 and 30 in the Go profile) drops its reload part.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
servers.md rule 8: configuration, TLS material and keys are read at start and changed by a rollout; the TI's verification data (TSL, TI roots, OCSP, federation statements and JWKS, IdP discovery) is the one run-time refresh, verified before use, swapped whole, kept on failure, its age a metric. Rules 6, 26 and 29 no longer ask for reload without restart. go/kv's file following is TASK-396.
<!-- SECTION:FINAL_SUMMARY:END -->
