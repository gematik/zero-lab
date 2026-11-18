---
id: decision-19
title: go/pdp is frozen; zeta-pdp-go replaces it
date: '2026-11-18 15:40'
status: accepted
---
## Context

go/pdp with its command zero-pdp is the prototype authorization server (policy decision point) of this repository. zeta-pdp-go replaces it and takes the shared modules (openid, oidf, dpop, nonce, kv, idpd) from here. go/pdp has since been left out of the work that went through every other Go module: encoding/json/v2 (TASK-323), the rule 28 audit (TASK-321) and the RFC 9700 check (TASK-259). Its last release is go/pdp v0.24.0.

## Decision

Maintainer, 2026-11-18: the development of go/pdp is frozen.

## Consequences

- No features, refactorings or fixes of audit findings land in go/pdp. A finding against it is not a task here; what it shows about an authorization server is checked in zeta-pdp-go.
- go/pdp stays in the workspace and in `just check`, so a change to a module it imports still has to compile and pass its tests, and `just sync` keeps its pins in step. A change in go/pdp that a shared module forces is the only kind that lands.
- No release of go/pdp or of the zero-pdp image is planned. go/pdp v0.24.0 and its image stay available and get no fixes; they are prototypes and not to be deployed.
- The rules of docs/ do not hold go/pdp to more than it meets today: it keeps encoding/json v1 and is out of scope of audits against servers.md.
- Removing go/pdp, with zero-pep-proxy's PDP backend and the pdp end-to-end suite that depend on an authorization server, is a later decision.
