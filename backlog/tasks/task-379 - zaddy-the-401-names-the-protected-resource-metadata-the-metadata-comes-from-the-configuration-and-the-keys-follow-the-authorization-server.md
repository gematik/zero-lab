---
id: TASK-379
title: >-
  zaddy: the 401 names the protected-resource metadata, the metadata comes from
  the configuration, and the keys follow the authorization server
status: Done
assignee: []
created_date: '2026-11-18 10:42'
updated_date: '2026-11-22 16:29'
labels:
  - zaddy
  - go
dependencies: []
references:
  - go/zaddy/zaddy.go
  - go/pep/pep.go
priority: medium
ordinal: 394000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Three things a deployment of zaddy has to do by hand today, seen on 2026-11-18 at directory-ref (zero-caddy 0.7.0, main the same; zeta-pdp-go TASK-125). (1) A request without a token is answered 401 with WWW-Authenticate: DPoP algs="ES256" and no resource_metadata parameter (RFC 9728 Section 5.1), so a client that starts at the resource is not told where the metadata is. (2) The metadata document is not served by the app that knows resource and authorization_server: the deployment writes the JSON into a respond directive, a second place for the same facts. (3) jwks_path is required and the file is read once at start (pep.Builder.WithJWKSetPath), although the option's comment says the keys of authorization_server are used without it: when the authorization server changes its signing key, tokens are refused until somebody replaces the file and reloads.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A 401 of enforce_policy carries resource_metadata with the URL of the protected-resource metadata
- [x] #2 zaddy serves the protected-resource metadata of its pep block (RFC 9728), with members a deployment can add, such as scopes_supported and zeta_asl_use
- [x] #3 Without jwks_path the keys are read at start from the jwks_uri of the authorization server's metadata (issuer checked, through the egress client) and read again when a token names an unknown kid, bounded in rate, a failed read keeping the set in force; with jwks_path the file is read once at start and a change is a rollout (servers.md rule 8)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
- AC #3 rewritten: the original "with jwks_path a changed file is taken without a restart" contradicts servers.md rule 8 (configuration and key files are read at start, a change is a rollout; no server watches or polls such a file). jwks_path stays read once at start.
- pep: every 401 challenge gets resource_metadata (RFC 9728 Section 5.1) in PEP.deny, appended as an auth-param to the single challenge (after the scheme when bare). URL derived from the resource as RFC 9728 Section 3.1 has it (pep.ProtectedResourceMetadataURL); Builder.ResourceMetadataURL overrides it; URLs a quoted-string cannot carry unescaped are refused. Bearer without Authorization now answers with a bare `Bearer` challenge so it can carry the parameter. 403s carry none. The session-cookie 401 (ErrSessionRequired) has no OAuth challenge and stays without one.
- pep: Builder.WithKeySource(pep.KeySource{Keys, Refresh(ctx)}); on errUnknownKeyID verifyAccessToken calls Refresh once and verifies again. pep imports no egress; the host bounds the rate.
- pep.ProtectedResourceMetadata gains Extra map[string]jsontext.Value (`json:",embed"`, the Go 1.27 json/v2 name for inline fallbacks); json.Deterministic orders it, a typed member name in Extra fails encoding; pep.IsProtectedResourceMetadataMember lists the typed names by reflection.
- zaddy: handler protected_resource_metadata (GET/HEAD, application/json, 405 with Allow otherwise), document encoded once at provision from resource, authorization_server, bearer_methods_supported [header], scopes_supported and metadata_member <name> <JSON>. Validate refuses typed names, invalid JSON, scopes outside RFC 6749 NQCHAR, and requires jwks_path or an https authorization_server without query/fragment.
- zaddy: authorizationServerKeys fetches RFC 8414 metadata (fallback /.well-known/openid-configuration on 404), exact issuer check (RFC 8414 Section 3.3), https jwks_uri, then the JWKS; through egress.NewClient, no redirects, status/Content-Type/size checks, openid.CheckJSONObject/UnmarshalObject bounds, only valid public keys, non-empty set. Fetched at App.Start (failure refuses start), every 15 min in the background, and on an unknown kid at most once per minute (fetch detached from the request's cancellation, serialised). A failed fetch keeps the set; it is logged, there is no metric yet (zaddy has no metrics).
- Deviation to note: the unknown-kid refetch runs on the request path, which servers.md rule 8 reserves for background refreshes; it is rate-bounded and was the decision for this task.
- zaddy gains requires on go/egress (authorised) and go/openid (for the shared jsontext bounds; only go-jose transitively, already present). Outside the workspace zaddy needs `just sync` for pep's new API.
- The dev Caddyfile serves the metadata with the new directive; zaddy/static/.well-known/oauth-protected-resource removed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
pep: every 401 challenge (Bearer and DPoP, bare or with an error) carries resource_metadata with the URL RFC 9728 Section 3.1 derives from the resource (Builder.ResourceMetadataURL overrides it); 403s carry none. pep.KeySource with Builder.WithKeySource lets a host refresh keys once when a token names an unknown kid. pep.ProtectedResourceMetadata takes deployment members in Extra, encoded deterministically, typed names refused.

zaddy: new handler protected_resource_metadata serves the document from the pep block (resource, authorization_servers, bearer_methods_supported, new scopes_supported and metadata_member subdirectives). Without jwks_path the keys come from the authorization server's RFC 8414 metadata (OIDC discovery fallback), issuer checked exactly, https jwks_uri, through the egress client; fetched at start (failure refuses start), every 15 minutes, and on an unknown kid at most once a minute; a failed fetch keeps the set. Validate requires jwks_path or an https authorization_server. AC #3 rewritten: jwks_path stays read once at start (servers.md rule 8).

Verified: go vet and go test -count=1 (and -race) for pep, zaddy, dpop; just check-changed clean. New tests: TestRFC9728_3_1_*, TestRFC9728_5_1_* (401 with and without path, 403, override), TestRFC9728_2_*, TestKeySource_*, TestRFC9728_3_2_*, TestServerRule28_TheMetadataRefusesOtherMethodsWith405, TestRFC8414_3_3_*, TestRFC8414_3_1_*, TestRFC8414_2_*, TestServerRule28_AKeySetThatIsNotPublicKeysIsRefused, TestServerRule8_AnUnknownKidRefetchesTheKeysAtMostOncePerInterval, TestServerRule17_ZaddyStartsOnlyWithTheAuthorizationServersKeys.

Left: zaddy's go.mod needs `just sync` after push (new requires on go/egress and go/openid, pep's new API); no metric for a failed key refresh yet, since zaddy has no metrics.
<!-- SECTION:FINAL_SUMMARY:END -->
