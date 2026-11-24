---
id: TASK-378
title: >-
  zaddy: hands on user and client as the ZETA PEP headers, and says what becomes
  of the client's credentials
status: In Progress
assignee: []
created_date: 2026-11-18 10:42
updated_date: '2026-11-24T19:06:00Z'
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
- [x] #1 With a directive of enforce_policy, the upstream gets zeta-user-info and zeta-client-data made from the verified token's claims, as the specification and its schemas (user-info, client-data) have them
- [x] #2 A header of these names that the client sent never reaches the upstream
- [x] #3 Authorization and DPoP of the client are passed on or removed as the specification says, and the README says which
- [ ] #4 metsubushi behind zaddy shows user and client of a token
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Spec: gemSpec_ZETA 1.3.2 (2026-06-26) A_25669-01, A_26589-01, A_26590-02, A_26492-02; schemas zeta-user-info.yaml and client-data.yaml (gematik/zeta).
1. pep: claims set by an enforcer inside all_of/any_of reach next (today WithDeny starts a context without them, so next never sees them); a failed any_of branch leaves no claims behind.
2. pep: ZETAUserInfo and ZETAClientData build the base64url JSON headers from the verified claims: identifier<-sub (the access token schema and zeta-pdp-go carry the identifier as sub; Tabelle 15 names it identifier), professionOID<-profession_oid, commonName<-common_name, organizationName<-organization_name; client_id, product_id, product_version, platform when one of the schema's values. Missing required claims is an error.
3. zaddy: enforce_policy subdirectives zeta_user_info and zeta_client_data (A_26492-02: client data per endpoint, default off). Client-sent zeta-user-info, zeta-client-data and zeta-popp-token-content are always removed. A token lacking the required claims is refused 403.
4. Authorization and DPoP are passed on: A_25669-01 forwards the request with all headers. README says so; PoPP is not supported, so zeta-popp-token-content is only removed.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented on feat/zaddy-zeta-headers. Found on the way: pep's all_of/any_of handed the next handler a context without the claims a token enforcer set (WithDeny made a fresh context), so nothing after the policy could read them; fixed with a shared claims cell, and any_of restores the claims after a denied branch. identifier comes from sub (access token schema and zeta-pdp-go), Tabelle 15 names the claim identifier. Base64-URL with padding as ngx_pep; metsubushi's decoder reads it (checked in node). AC 4 needs the live run behind zero-caddy with tokens of zeta-pdp-go.
<!-- SECTION:NOTES:END -->
