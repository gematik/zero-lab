---
id: TASK-378
title: >-
  zaddy: hands on user and client as the ZETA PEP headers, and says what becomes
  of the client's credentials
status: To Do
assignee: []
created_date: '2026-11-18 10:42'
labels:
  - zaddy
  - go
  - spec
dependencies: []
references:
  - go/zaddy/enforce_policy.go
  - go/metsubushi/README.md
priority: medium
ordinal: 393000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zaddy's enforce_policy verifies the access token and its DPoP proof and then passes the request on as it came. Seen on 2026-11-18 at directory-ref (zero-caddy 0.7.0 in front of metsubushi, tokens of zeta-pdp-go; zeta-pdp-go TASK-125): the upstream got the client's Authorization and DPoP headers unchanged and none of the headers a ZETA PEP HTTP proxy adds (A_25669-01, as go/metsubushi/README.md lists them: zeta-user-info, zeta-client-data, zeta-popp-token-content, each base64url of JSON), so metsubushi has nothing to show of user or client. main is the same: nothing in go/zaddy or go/pep writes these headers or removes a credential. What the specification says of the access token and the proof on the way to the service is to be read in the task (gemSpec_ZETA, PEP HTTP proxy), not assumed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 With a directive of enforce_policy, the upstream gets zeta-user-info and zeta-client-data made from the verified token's claims, as the specification and its schemas (user-info, client-data) have them
- [ ] #2 A header of these names that the client sent never reaches the upstream
- [ ] #3 Authorization and DPoP of the client are passed on or removed as the specification says, and the README says which
- [ ] #4 metsubushi behind zaddy shows user and client of a token
<!-- AC:END -->
