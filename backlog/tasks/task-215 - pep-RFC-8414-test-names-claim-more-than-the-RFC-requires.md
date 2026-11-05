---
id: TASK-215
title: 'pep: RFC 8414 test names claim more than the RFC requires'
status: Done
assignee: []
created_date: '2026-11-05T21:24:00Z'
updated_date: '2026-11-05T21:32:00Z'
labels:
  - go
dependencies: []
ordinal: 222000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TestRFC8414_MetadataOfAnHTTPSIssuerNeedsHTTPSEndpoints and its sibling cite RFC 8414, which requires https only for the issuer and jwks_uri (Section 2), not for every endpoint. Found while naming tests (TASK-83).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the tests cite the rule that requires https endpoints, or are split into an RFC 8414 test and a test of our own policy
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On test/pep-rfc8414-names (5f98a1b8). Split by rule: TestRFC6749_10_9_AuthorizationAndTokenEndpointsMustBeHTTPS, TestRFC9126_2_ThePushedAuthorizationRequestEndpointMustBeHTTPS, TestMetadataOfAnHTTPSIssuerNamesNoPlainEndpoint (our policy: introspection, nonce, openid_providers; RFC 7662 Section 4 only asks the server to support TLS). The positive test and the loopback exception lost the RFC 8414 prefix. RFC texts checked from rfc-editor.org.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The https endpoint tests cite RFC 6749 Section 10.9 (authorization, token), RFC 9126 Section 2 (PAR) or our policy (introspection, nonce, openid_providers); tests no rule requires lost the RFC 8414 prefix. Merged into main as 5f98a1b8.
<!-- SECTION:FINAL_SUMMARY:END -->
