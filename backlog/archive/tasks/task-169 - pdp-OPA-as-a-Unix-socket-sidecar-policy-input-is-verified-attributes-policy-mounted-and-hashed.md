---
id: TASK-169
title: >-
  pdp: OPA as a Unix-socket sidecar; policy input is verified attributes; policy
  mounted and hashed
status: To Do
assignee: []
created_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - pdp
dependencies: []
priority: medium
ordinal: 179000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The PDP's authorization decisions move to Open Policy Agent (maintainer, 2026-11-01). OPA runs as a sidecar container in the PDP's pod with its server on a Unix socket in a shared emptyDir (opa run --server --addr unix://...), never on the network; the PDP's client is standard library only (net/http over a Unix socket). The policy input is what the PDP has verified (client, scopes, the SMC-B verdict's Telematik-ID and profession OIDs, DPoP binding), never raw certificates or tokens. Policies and data are configuration mounted at start, hashed and reported (servers.md rule 7), never loaded at runtime (rule 7, no code loaded at runtime) and never fetched from a bundle server. Weighed and rejected in doc-2: embedding the OPA Go module (dependency tree against docs/conventions/dependencies.md) and OPA-compiled Wasm (needs a runtime, rejected by decision-10). Fail closed on an unreachable OPA (rule 16). Rules: docs/design/servers.md 4, 7, 8, 16.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 OPA reached over a Unix socket only; the PDP refuses to start with a network OPA address in production
- [ ] #2 policy input schema documented and versioned; no certificate or token bytes in it
- [ ] #3 policy and data mounted read-only, their digest in the start-up report; an unreachable or erroring OPA denies
- [ ] #4 the pod spec and a compose file carry the sidecar from the OPA image pinned by digest
<!-- AC:END -->
