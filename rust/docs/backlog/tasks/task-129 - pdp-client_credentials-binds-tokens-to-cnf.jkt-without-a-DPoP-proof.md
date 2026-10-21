---
id: TASK-129
title: 'pdp: client_credentials binds tokens to cnf.jkt without a DPoP proof'
status: Done
assignee: []
created_date: '2026-10-21 07:53'
updated_date: '2026-10-21 08:52'
labels:
  - go
  - pdp
  - security
dependencies: []
priority: high
ordinal: 140000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RFC 9449 Section 5: a client MUST provide a valid DPoP proof 'for all access token requests regardless of grant type'. pdp checks the proof (verifyDPoPBinding, go/dpop Verifier) only on the authorization code exchange; on client_credentials it issues a DPoP-bound token (token_type DPoP, cnf.jkt) for a key the client assertion merely names (TestPrivateKeyJWTClientCredentials asserts exactly that). A party holding only the client's signing key could thus bind tokens to any key. Check the proof on every grant that issues a DPoP-bound token, with the asserted cnf.jkt as Request.Thumbprint.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 every token request that yields a DPoP-bound token carries a proof verified by the dpop Verifier for the token endpoint and the bound key; without one the request is refused or the token is not DPoP-bound
- [x] #2 TestPrivateKeyJWTClientCredentials signs a proof; a test without a proof is refused
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
pdp decides the DPoP binding in one place, dpopBinding, for all three grants (RFC 9449 Section 5: "all access token requests regardless of grant type"): a proof is checked whenever the request carries one or the client assertion names cnf.jkt, and must then be signed by that key; tokens are bound to the proof key. client_credentials no longer binds to a named key without a proof. Refresh of a bound session needs a proof by the session key; an unbound session is not bound later. Tests: TestRFC9449_5_ClientCredentialsWithoutProofIsRefused, _ProofByAnotherKeyIsRefused, _ProofForAnotherEndpointIsRefused (all fail on the old code), TestPrivateKeyJWTClientCredentials with a real proof; the gated pdp e2e suite signs proofs and passes against a local pdp (ZERO_PDP_E2E_SCOPE=e2e; go/.env sets another scope).
<!-- SECTION:FINAL_SUMMARY:END -->
