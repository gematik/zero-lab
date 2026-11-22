---
id: TASK-379
title: >-
  zaddy: the 401 names the protected-resource metadata, the metadata comes from
  the configuration, and the keys follow the authorization server
status: In Progress
assignee: []
created_date: '2026-11-18 10:42'
updated_date: '2026-11-22 16:06'
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
- [ ] #1 A 401 of enforce_policy carries resource_metadata with the URL of the protected-resource metadata
- [ ] #2 zaddy serves the protected-resource metadata of its pep block (RFC 9728), with members a deployment can add, such as scopes_supported and zeta_asl_use
- [ ] #3 Without jwks_path the keys are read from the jwks_uri of the authorization server's metadata and read again when a token names an unknown kid, bounded in rate; with jwks_path a changed file is taken without a restart
<!-- AC:END -->
