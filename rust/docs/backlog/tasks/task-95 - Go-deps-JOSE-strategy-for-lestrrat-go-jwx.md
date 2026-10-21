---
id: TASK-95
title: 'Go deps: JOSE strategy for lestrrat-go/jwx'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
updated_date: '2026-10-21 07:15'
labels:
  - go
  - deps
  - design
dependencies:
  - TASK-126
references:
  - docs/conventions/dependencies.md
  - go/docs/design.md
priority: high
ordinal: 93000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwx is the largest unaudited cryptographic dependency, has one maintainer, and is a second JOSE implementation next to brainpool/josebp.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decided with the maintainer: go-jose, extending josebp on the standard library, or the Rust jwz through ti; plan per module
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision (maintainer, 2026-10-21): go-jose/go-jose/v4 replaces lestrrat-go/jwx.
Measured (v4.1.6 vs jwx v3.3.0): 11,361 vs 38,041 non-test lines; 0 vs 9 third-party modules (jwx pulls testify, go.yaml.in/yaml, fastjson, x/crypto and five lestrrat-go modules into production builds); neither imports unsafe; go-jose is maintained by an organisation, jwx by one person.
Security defaults: go-jose requires an algorithm allowlist on every ParseSigned/ParseEncrypted (today pep and oauth/oidc infer the algorithm from the key), has no none, rejects unknown crit, caps decompression (250 kB / 10x) and p2c; claims are validated only when called (ValidateWithLeeway), so each module wraps signature, allowlist and claims in one helper and tests that an expired token fails.
josebp: stays for brainpool in gemidp. On go-jose only signing and verifying would fit (OpaqueSigner/OpaqueVerifier); BP-256 JWKs (go-jose knows P-256/384/521 only) and ECDH-ES encryption to a BP-256 key (OpaqueKeyEncrypter cannot be implemented outside go-jose) would not, so adapting it saves little. gemidp may later move to the Rust ti through the helpers.
bff: not migrated, deleted in favour of pep (TASK-127).
JWKS: not part of go-jose; a JWKS provider on cached HTTP content shared with Rust (TASK-125, TASK-126).
Plan, one PR per step: dpop; oauth (after TASK-126); bff skipped (TASK-127); oidf; pep (session cookies and snapshots: dir+A256GCM, consider crypto/cipher directly, TASK-71); pdp; gemidp drops jwx (josebp only). Done when no go.mod requires jwx.
<!-- SECTION:NOTES:END -->
