---
id: TASK-376
title: >-
  oidf: a signed key set without exp is taken, bounded by the entity statement
  of its issuer
status: Done
assignee: []
created_date: '2026-11-18 08:21'
updated_date: '2026-11-18 08:45'
labels:
  - oidf
  - go
  - spec
dependencies: []
references:
  - go/oidf/oidf.go
  - docs/design/servers.md
priority: medium
ordinal: 391000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FetchSignedJwks refuses a signed key set that states no exp (requireExpiry, go/oidf/oidf.go: 'a signed key set or IdP list has to state its exp'). The federation specification leaves exp of a signed JWK set optional; the check is this module's own, by server rule 15, so that a key set an OP has replaced cannot be replayed for ever.

The gematik reference IDP of the reference federation (https://gsi-ref.dev.gematik.solutions, in the master's IdP list) publishes its key set at /jws.json with typ jwk-set+json and the members iss, iat and keys, and no exp. A relying party on this module therefore cannot begin a login there: zeta-pdp-go as directory-ref answered 503 on 2026-11-18 with 'the signed JWKS: a signed key set or IdP list has to state its exp' (zeta-pdp-go TASK-124). An IDP that follows the specification is locked out by a rule the specification does not have.

The maintainer decided on 2026-11-18 to relax the module. A key set without exp is not without a bound: it is verified with the keys of the issuer's entity statement, which states its own exp, and iat says when it was signed. What the bound is (the statement's exp, a maximum age from iat, or the shorter of both) is to be settled in the task and written next to the code. The IdP list of the master keeps its mandatory exp (gemSpec_IDP_FedMaster Tabelle 8).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A signed key set without exp from an OP of the federation is taken, and a login at https://gsi-ref.dev.gematik.solutions can begin
- [x] #2 A key set without exp is kept and used no longer than a stated bound that does not outlast the entity statement it was verified with; the bound is documented at the check and tested
- [x] #3 A key set that states exp is held to it as before, and an expired one is refused
- [x] #4 The IdP list without exp is still refused
- [x] #5 docs/design/servers.md rule 15 or the module's documentation says where this module is no stricter than the specification and why
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Bound settled: a key set without exp is never kept in the document store (keep already skips a document without exp), so it lives for the one call that fetched it and is verified with the keys of the statement that call was given; this cannot outlast the statement. Cost: one fetch of the key set per resolution at such a provider, single-flighted by fetchOnce. Documented at FetchSignedJwks; servers.md rule 15 already allows a documented interoperability need. requireExpiry is gone; the IdP list checks its exp in parseIdpList. Live on 2026-11-18: all 108 IdPs of app-ref.federationmaster.de and all 119 of app.federationmaster.de verify; without exp are gsi-ref.dev.gematik.solutions and sidp-c01-ru.d-trust.net/realms/sidpdtr01 (ref only). Released as go/oidf v0.54.2; pdp and pep/proxy pin it.
<!-- SECTION:NOTES:END -->
