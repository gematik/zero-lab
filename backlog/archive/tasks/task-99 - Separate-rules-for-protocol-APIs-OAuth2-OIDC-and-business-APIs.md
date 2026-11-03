---
id: TASK-99
title: 'Separate rules for protocol APIs (OAuth 2.0, OIDC) and business APIs'
status: To Do
assignee: []
created_date: '2026-10-15 05:35'
labels:
  - api
  - spec
  - docs
dependencies: []
references:
  - docs/design/servers.md
  - docs/conventions/naming-and-config.md
priority: medium
ordinal: 97000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The gematik OpenAPI ruleset is written for business APIs: versioned paths, kebab-case paths, snake_case query parameters, Hyphenated-Pascal headers. Protocol APIs (OAuth 2.0, OpenID Connect, OpenID Federation, PAR, DPoP, token introspection, later OID4VCI/OID4VP) are defined by their standards and security profiles instead: their paths (/.well-known/...), parameter names, header names (DPoP) and JSON members (snake_case) are fixed there, and they are not versioned by path. Running the business rules on them yields findings nobody may act on. The repository needs two rule sets, each with its own contract and checks, and every API classified as one or the other. This is a question of the rules, not of changing zero-lab's endpoints.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 docs/design/servers.md distinguishes protocol APIs and business APIs: business APIs follow the gematik API rules with versioning (rule 18); protocol APIs follow their standards and the hardened profiles of rule 15 (RFC 6749, RFC 8414, RFC 9126, RFC 9449, RFC 9700, FAPI 2.0, OpenID Connect, OpenID Federation, HAIP, the gematik IDP-Dienst and ZETA profiles), with names and paths from the specification
- [ ] #2 the contract of a protocol API is the standard plus a conformance description (a spec in spec/ or a conformance test suite against the profile), not an OpenAPI business contract; where an OpenAPI description exists for documentation, it is not linted with the business rules
- [ ] #3 every API of the repository is classified (protocol or business), and the classification is recorded next to its contract
- [ ] #4 just api-lint lints business API contracts only, and a conformance check exists for the protocol APIs (for example the pdp e2e suites or an OpenID conformance run)
<!-- AC:END -->
