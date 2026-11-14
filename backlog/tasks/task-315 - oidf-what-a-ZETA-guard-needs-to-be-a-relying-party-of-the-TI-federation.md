---
id: TASK-315
title: 'oidf: what a ZETA guard needs to be a relying party of the TI federation'
status: To Do
assignee: []
created_date: '2026-11-14T20:17:00Z'
labels: []
dependencies: []
ordinal: 330000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by zeta-pdp-go (its block C: tasks 53 to 55, login through a sektoral IDP; survey of 2026-11-14 against go/oidf at 76b3bc8c). zeta-pdp-go builds the client-facing half itself (pushed authorization request, authorization and redirection endpoint, authorization_code grant) and wants go/oidf for the IDP leg: entity statement, resolving the IDP, PAR and token request at the IDP, the ID token. Four things block that and have no reasonable workaround on its side; the rest it could work around and should not have to.

Blocking:
1. The entity statement cannot say what as-entity-statement.yaml of gemSpec_ZETA requires. Since a71b36d3 (2026-06-26) the metadata is typed config plus Go defaults in place of the untyped metadata_template, which made the invariants safe and closed the set of members: Metadata (entity_statement.go:53) has no oauth_authorization_server (required: issuer and jwks_uri, signed_jwks_uri or jwks with the token signing key, A_25668-01); OpenIDRelyingPartyMetadata (:88) has no keywords, contacts, ti_features_supported; federation_entity has no organization_name; hooks see only these structs; empty logo_uri and organization_name are written as "". Wanted: the typed defaults stay, and a caller can add members and whole metadata types (typed fields for what ZETA names, and an open map beside them), with empty optional members left out. Also from the schema: exp minus iat at most 86400 (A_28857), kid as the caller sets it (UUIDv7 there).
2. The request to the IDP is not per login: acr_values is fixed (client.go:59), scopes come from the configuration, and there is no claims parameter, which gemSpec_ZETA 5.3.2.5 step 12 sends. Wanted on openid.Login or beside it: acr_values, scope and claims per login. (Overlaps TASK-296.)
3. Keys are files or inline JWKs (KeyConfig, relying_party.go:99): no crypto.Signer for the federation signing key, no crypto.Decrypter for the ID token key, the TLS client certificate only as a PEM file. zeta-pdp-go hands keys in as crypto.Signer so that an HSM can hold them. Wanted: a constructor that takes them so; rotation is not asked here. (Overlaps TASK-294.)
4. No tag has the injected Clock (RelyingPartyConfig.Clock is after go/oidf/v0.51.0). Wanted: a release with the above.

Should be here, could be worked around:
5. Nothing is cached: Provider() fetches the master's statement about the IDP, the IDP's statement and its signed JWKS on every call (relying_party.go:393), twice per login; the master's federation_entity is read once and never again (oidf.go:231). Wanted: statements and JWKS kept until they expire, refetched on an unknown kid (A_22861). A cache per process is enough for a start. (TASK-293.)
6. The ID token's claims come out untyped and acr, amr and auth_time are not checked (client.go:132, openid/claims.go:51). Wanted: typed claims (urn:telematik:claims:id, display_name, profession, organization, birthdate, acr, amr, auth_time) and a refusal of an acr below the one asked for (A_26973, A_29994). (TASK-296.)
7. The IDP is not checked for admission: idp_iss is not looked up in the master's list and user_type is dropped (kind.go:56, TODO at relying_party.go:399; A_25449). (TASK-297.)
8. Federation fetches ignore the context (oidf.go:240), so they are not cancelled with the request.
9. The trust anchor is a base URL and a JWK, built in for three masters (relying_party.go:132); ZETA's provisioning gives federation-master.json with an entity_statement_uri per environment and no key. Wanted: accept the statement URI; say how a master outside the table gets its key.
10. There is no test double another module can import: federationStub is test code of this package (federation_test.go:84), authzserver/mockidp is plain OIDC behind a build tag. Wanted: an exported test federation with one sektoral IDP (master, statements, signed JWKS, PAR, mTLS, ID token signed and encrypted) for the tests of a relying party built on this module.

Not needed by zeta-pdp-go: decryption on brainpool (TASK-299; the schema asks P-256 keys of the relying party and keycloak-zeta uses P-256, so that task can be closed on this evidence), trust chains beyond one hop and metadata policy (TASK-291, TASK-292; a guard registers with the master directly).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A caller can serve an entity statement that validates against as-entity-statement.yaml of gemSpec_ZETA 2.0.0, with oauth_authorization_server metadata
- [ ] #2 acr_values, scope and claims are set per login
- [ ] #3 Signing, decryption and TLS client keys can be handed in as crypto.Signer and crypto.Decrypter
- [ ] #4 Statements and JWKS are cached until they expire; fetches take the context
- [ ] #5 ID token claims are typed; a lower acr than asked for is refused; an IDP that is not on the master's list or not of an accepted user type is refused
- [ ] #6 An exported test federation with a sektoral IDP exists
- [ ] #7 A tag of go/oidf carries it
<!-- AC:END -->
