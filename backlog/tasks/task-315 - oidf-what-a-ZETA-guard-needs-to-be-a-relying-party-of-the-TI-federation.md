---
id: TASK-315
title: 'oidf: what a ZETA guard needs to be a relying party of the TI federation'
status: Done
assignee: []
created_date: '2026-11-14T20:17:00Z'
updated_date: '2026-11-15T13:46:00Z'
labels:
  - oidf
  - go
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
- [x] #1 A caller can add any member and whole entity types to the served entity statement through the hook; empty optional members are left out; exp minus iat is at most 86400 s; kids as the caller sets them
- [x] #2 acr_values, scope and claims are set per login; state and nonce beyond 512 base64url characters are refused before the request
- [x] #3 Signing and TLS client keys can be handed in as crypto.Signer, the ID token key as an ECDH key agreement (ECDH-ES is no decryption, so not a crypto.Decrypter)
- [x] #4 Statements, signed JWKS and the IdP list are kept in a store interface of oidf's own terms, wired by the hosts, verified again on every read; fetches take the context
- [x] #5 ID token claims are typed; a lower acr than asked for is refused; an IDP that is not on the master's IdP list or not an openid_provider is refused
- [x] #6 An exported test federation with a sektoral IDP exists
- [x] #7 The entity statement and signed JWKS are signed once and served as bytes, re-signed on age or change
- [x] #8 A tag of go/oidf carries it
- [x] #9 Every request value to and from the IDP is validated against an allowlist before use (OWASP input validation: reject, never repair; errors name the field, not the value); fuzz targets with nasty-input seeds cover each entry point
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Plan approved 2026-11-14 (maintainer). Branch feat/oidf-rp. No ZETA names in go/oidf: ZETA's members (keywords, contacts, ti_features_supported, oauth_authorization_server) come from zeta-pdp-go through the hook; the ZETA schema proof is zeta-pdp-go's conformance.
1. openid: Login gets Scopes, ACRValues, Claims; AuthorizationQuery validates claims (JSON object, 4 KiB) and returns an error.
2. oidf: ctx on every fetch; Documents store (Get/Keep), every read verified again, single-flight per URL, master statement refetched on expiry; NewMemoryDocuments; Kind takes the store.
3. oidf: Keys{Sign crypto.Signer, Decrypt KeyAgreement, Client tls.Certificate, kids}; New(ctx, cfg, keys); ES256 through cryptosigner; ECDH-ES through an OpaqueKeyDecrypter with Concat KDF; NewRelyingParty loads files and calls New.
4. oidf: Extra members on metadata and Metadata, hook with error on a deep copy; checks at signing (shadowing, iss=sub, kid in jwks, no d); omitempty; jwks or signed_jwks_uri; lifetime constant (A_28857).
4b. oidf: statement and signed JWKS signed once, served as bytes (atomic), re-signed after 1 h or on Refresh, single-flight, last good until exp then 503, ETag/304/Cache-Control/HEAD, Content-Type with charset (FEDM_FD_REG), no per-request log.
5. oidf: Client(ctx, issuer) admits by the master's IdP list before any fetch at the issuer, requires openid_provider; PAR with per-login scope/acr/claims checked against registration and the LoA set, state/nonce bounds; ExchangeIdentity with typed Identity, acr not below the asked, amr and auth_time required, one rate-limited refetch on an unknown kid (A_22861); trust anchor from the master's statement URI.
6. oidf/oidftest: master and one sektoral IDP over TLS with mTLS, PAR, authorize, token, signed and encrypted ID token, knobs; mod-check guard that no non-test package imports oidftest or epatest.
7. pdp and pep/proxy wire a kv-backed Documents.
8. Release openid, oidf, pdp, pep/proxy after full just check, review, oidf-test (maintainer) and a live TK login.
Full plan: ~/.claude/plans/cheerful-tickling-bear.md

5b (maintainer, 2026-11-14): OWASP input validation of every request value to and from the IDP (state, nonce, verifier, scope, acr, claims, redirect_uri exact, code, idp_iss, PAR/token/error responses, ID token claim strings), reject never repair, sentinel errors without the value; fuzz targets per entry point with CRLF/NUL/overlong/invalid-UTF-8/bidi/encoded-separator/nested-JSON seeds, asserting properties.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-14, from zeta-pdp-go, two more sources:
- gematik/app-FedIdpTestsuite (features/fachdienstRegistration.feature, FEDM_FD_REG_001 to 005) is what a relying party's entity statement is tested with before registration: Content-Type application/entity-statement+jwt;charset=UTF-8, header alg ES256 with kid and typ entity-statement+jwt, claims iss, sub, iat, exp, jwks, authority_hints (the master first), metadata with openid_relying_party and federation_entity. Worth running against what this module serves.
- State towards a sektoral IDP must be short and of the base64url alphabet. Measured on 2026-11-14 with pushed requests as a registered relying party of the reference federation: BMS and T-Systems IDPs refuse a state of 513 characters and take 512; IBM takes 8192. gematik/ref-idp-server has the same bound for its own endpoint (IdpController: state and nonce ^[_\-a-zA-Z0-9]{1,512}$, code_verifier at most 128), and its test suite says the bound comes from RISE's concept, not from a requirement. All three IDPs return a short random request_uri (27 to 60 characters) that lasts 90 seconds.

2026-11-15: merged to main (1fc214c7), repinned (a01d0b31), full just check green on main. Open: AC #8, the tags, after the maintainer's just oidf-test and a live TK login.

Released 2026-11-15: openid v0.54.0, oidf v0.52.0, pkcs12 v1.0.0-rc.3, pep/proxy v0.3.0. Gated: just oidf-test and TestNewAtALiveFederationMaster against app-ref, kv on Postgres, PDP e2e locally (OIDF statement checks against the rathole config), live TK RU2 login on zerobin (0.3.0-dev.51a0bb8). pdp not tagged yet: PDP HITL outstanding.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/oidf v0.52.0 (with openid v0.54.0) is a relying party of the TI federation that a ZETA guard builds on: keys as functions (Signer, ECDH KeyAgreement, tls.Certificate), a host-wired store of verified federation documents, admission by the master IdP list, typed Identity with acr/amr checks, statement signed once and served as bytes, rule-28 input validation with fuzz targets, oidftest. pep/proxy v0.3.0 carries it; live TK RU2 login passed on zerobin. pdp tag waits for the PDP HITL.
<!-- SECTION:FINAL_SUMMARY:END -->
