---
id: TASK-30
title: 'ti-directory: FHIR-Directory owner authentication through the IDP-Dienst'
status: Done
assignee: []
created_date: '2026-10-10 19:15'
updated_date: '2026-10-10 20:41'
labels:
  - ti-directory
  - ti-cli
dependencies: []
priority: medium
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The FHIR-Directory (VZD) authenticates owners (SMC-B, HBA) with the IDP-Dienst: GET /owner-authenticate redirects to the IDP's authorization URL (the directory is the relying party, client_id opaque), the Authenticator-Modul flow yields the code, and GET /signin-gematik-idp-dienst?code&state answers with the owner access token (ES256 JWT, 24 h, sub = Telematik-ID) for /owner and /search. New crate ti-directory (sans I/O over ti-idpd's HTTP types) and ti directory login --env|--url --idp-url <identity>. Guards: the directory's redirect must go to the environment's IDP, the IDP's redirect back to the directory's sign-in endpoint. No token cache (a bearer token is a secret). Decoupled variants (gematik Authenticator app) out of scope. Spec: gemSpec_VZD_FHIR_Directory V1.7.0, gematik/api-vzd I_VZD_Owner.yaml 1.0.2, FHIR_VZD_HOWTO_Authenticate.adoc.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti directory login yields an owner access token against the RU FHIR-Directory with the test SMC-B (P12) and with SMC-B-7 at the Konnektor (HITL)
- [x] #2 the token is accepted by the RU directory's /owner endpoint (HITL curl)
- [x] #3 loopback end-to-end tests cover the token, the foreign-IDP guard, the directory's refusal and the IDP's refusal; just check green
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
HITL 2026-10-10 against RU: login with the P12 of 80276883110000100001 (SMC-B57, Telematik-ID 1-20014242424) yields an owner token (scope owner:read owner:write search:read link:* certificate:read log:read); GET /owner/Organization with it answers 200 with a Bundle; the user proved the same with the card at the Konnektor. Test SMC-Bs without a directory entry are refused at the sign-in with HTTP 403 'Validation Failure: Unknown Telematik ID' (errors: null), now reported as directory_error. probe gained kind directory: /owner-authenticate redirects to the environment's IDP in ref, test (fhir-directory-tu) and prod.
<!-- SECTION:NOTES:END -->
