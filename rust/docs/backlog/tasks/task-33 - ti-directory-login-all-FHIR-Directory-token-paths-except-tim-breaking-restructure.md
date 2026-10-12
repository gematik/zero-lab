---
id: TASK-33
title: >-
  ti directory login: all FHIR-Directory token paths except tim (breaking
  restructure)
status: Done
assignee: []
created_date: '2026-10-11 11:40'
updated_date: '2026-10-12 16:52'
labels:
  - ti-directory
  - ti-cli
dependencies: []
priority: high
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti directory login covers only the owner path by card. The FHIR-Directory (gemSpec_VZD_FHIR_Directory V1.7.0, gematik/api-vzd FHIR_VZD_HOWTO_Authenticate, I_VZD_Owner) issues tokens on further paths, all checked live on RU 2026-10-11 (endpoints answer, Keycloak realms reachable at auth[-ref|-test].vzd.ti-dienste.de:9443). Restructure into one subcommand per directory endpoint, named like the endpoint and the token's iss (decision-5): login owner (card via the IDP-Dienst, as today; --decoupled for the gematik Authenticator: POST /owner-authenticate-decoupled, print redirect_uri, poll /owner-authenticate-poll with auth_req_id; --regservice-token-path FILE: GET /owner-authenticate with a TIM RegService-OpenID-Token as Bearer), login holder (client credentials at realm RSDirectoryAdministration, then GET /holder-authenticate), login service (realm Service-Authenticate, then /service-authenticate), login ti-provider (realm TI-Provider, Keycloak token valid 5 min, then /ti-provider-authenticate). Secrets only from files: --client-secret-path / TI_DIRECTORY_CLIENT_SECRET_PATH, --client-id / TI_DIRECTORY_CLIENT_ID. One report and schema (directory login) for all paths: endpoint (iss), access_token, expires_in, expires_at, decoded token claims, plus identity/idp/challenge for the card path and client_id for client credentials; --token prints only the access token. --url overrides the directory, --auth-url the Keycloak host (TU: directory fhir-directory-tu, Keycloak auth-test). New error kind directory_auth_server_error for Keycloak refusals. ti-directory: OwnerToken becomes AccessToken; sans-I/O modules keycloak (client credentials), exchange (Bearer GET), decoupled (backchannel POST and poll). Breaking: ti directory login --env … becomes ti directory login owner --env …. Not in scope: tim (/tim-authenticate with a Matrix OpenID token).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 login owner (card) works as before under the new name; login owner --decoupled prints the Authenticator link and polls to a token; login owner --regservice-token-path exchanges a RegService-OpenID-Token
- [x] #2 login holder, login service and login ti-provider obtain a Keycloak token with client credentials from a secret file and exchange it at their endpoint; a wrong secret is directory_auth_server_error
- [x] #3 one directory login schema for every path, --token prints the bare token; loopback tests with fake Keycloak and directory for each path; just check green
- [x] #4 HITL against RU for owner by card and for every client-credentials realm credentials exist for
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-10-11: --decoupled removed again at the user's request: this tool is the Authenticator-Modul itself, and answering an IDP authorization URL belongs to ti idpd (idpd authenticate --auth-url), not to directory login. AC1's decoupled part is dropped.

HITL 2026-10-12 against RU: ti directory login owner --env ref --card SMC-B-7 --token works (user). Client credentials: no RU credentials at hand; the live path was checked with wrong credentials (Keycloak's invalid_client as directory_auth_server_error) and end to end against the loopback Keycloak; the RegService exchange reached RU and was refused for a dummy token as expected. Released in ti-cli 0.4.0.
<!-- SECTION:NOTES:END -->
