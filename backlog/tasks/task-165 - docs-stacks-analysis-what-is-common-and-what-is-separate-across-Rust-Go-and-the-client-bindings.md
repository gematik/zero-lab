---
id: TASK-165
title: >-
  docs: stacks analysis, what is common and what is separate across Rust, Go and
  the client bindings
status: In Progress
assignee: []
created_date: '2026-11-01T16:10:00Z'
updated_date: '2026-11-01T16:17:00Z'
labels:
  - docs
  - interop
  - rust
  - go
dependencies: []
priority: medium
ordinal: 175000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Go PDP is to gain token exchange with an SMC-B client proof, which needs the full TI certificate check (brainpool signature, chain to a TSL-listed CA under a roots.json root, C.HCI.AUT profile, OCSP, admission extension). None of it exists in Go (gempki is archived); all of it is in ti-pki. doc-1 predicted per-request work native in Go and the rest through a Rust process; this is the first case in the grey zone. The maintainer asked for an analysis that settles it and gives the rule for every stack: Rust and Go primary; JVM, .NET, iOS and Android as client bindings only; important TI functions isolated in every stack; in Go a per-function decision between a native implementation under a shared spec and a Rust helper. Brainstormed 2026-11-01 with the maintainer; the positions are in the plan below and land as backlog doc-2, decision-10 and rule changes under docs/.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 doc-2 written with the positions of the plan, every fact with its source and date
- [x] #2 decision-10 recorded; draft decision-8 of the spike branch absorbed
- [x] #3 rules updated in their owning documents (architecture, languages, interop, servers, conventions) and mapped in both profiles; no rule in two documents
- [x] #4 follow-up tasks created and existing tasks updated with the 2026-11-01 decisions
- [ ] #5 maintainer reviewed doc-2 and decision-10 (HITL of this task)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. doc-2 'Stacks: what is common, what is separate': inventory of TI functions per host and stack; the isolation rule (unit shape, renewal policy in the unit, transport from the host); ways to reach the core per host class with the TASK-116 numbers; the zero-trust PDP and the helper (A Go-native, B stateless helper, C wasm2go; recommendation B); the detached TSL signature and its consequence; OPA as a Unix-socket sidecar; HSM mutual binding; the stateless helper shape; trust-material producer and consumers in Docker and Kubernetes (CronJob to ConfigMap, air-gapped import); risk reduction for anything implemented twice; consequences and open points. 2. decision-10: stateless helpers in the same image over stdio or a Unix socket; the Go decision procedure; absorbs the spike's draft decision-8. 3. Rule changes: architecture.md (isolated TI functions, .NET, clients-only bindings), languages.md, interop.md (helpers, decision procedure), servers.md (one image several deployments, HSM binding, OPA), conventions (helper naming, libexec layout), both profiles. 4. Tasks: the detached-signature task (high), token exchange, OPA, HSM, gemidp certificate verification, .NET profile, trust-material producer; TASK-88, TASK-97, TASK-120.x, TASK-26, TASK-57, TASK-65, TASK-66 updated; doc-1 pointer. 5. Review against docs/principles.md and the one-owner rule of docs/README.md.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01: doc-2 written (12 sections: inventory, isolation rule, bridges with the TASK-116 numbers, the zero-trust PDP and the helper with A/B/C weighed, the detached TSL signature with the TUC_PKI_012 deviation, OPA, HSM, helper shape, trust-material producer and consumers, risk reduction, consequences). decision-10 accepted, absorbing the spike's decision-8. Rules changed in docs/architecture.md (isolated TI functions, .NET, clients-only bindings), docs/languages.md, docs/interop.md (helpers, the Go decision procedure, tsl-detached candidate), docs/design/servers.md (one image several deployments, sidecar rules, HSM binding, producer of trust material), docs/conventions/naming-and-config.md (helpers), docs/conventions/git-and-releases.md (helpers in images), docs/README.md, CLAUDE.md, go/docs/design.md, rust/docs/design.md, rust/docs/development.md. Tasks: TASK-166 to TASK-173 created; TASK-88 (high, random-key finding), TASK-97, TASK-120, 120.1, 120.4, 120.6, 120.7, TASK-26, TASK-57, TASK-65, TASK-66 updated; doc-1 pointer. Facts checked live: the nine .xml/.sig/.ocsp URLs answered 200, the .sig structure decoded with openssl asn1parse, the TSL signer anchors confirmed in anchors.rs. Links in the changed documents resolve. Awaiting the maintainer's review (criterion 5).
<!-- SECTION:NOTES:END -->
