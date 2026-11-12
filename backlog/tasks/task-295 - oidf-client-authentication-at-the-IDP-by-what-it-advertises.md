---
id: TASK-295
title: 'oidf: client authentication at the IDP by what it advertises'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
labels: []
dependencies: []
ordinal: 311000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Towards the IDP only self_signed_tls_client_auth is implemented and written into the entity statement. private_key_jwt is not, and the provider's token_endpoint_auth_methods_supported is not consulted. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The relying party authenticates with a method the provider supports, private_key_jwt among them
<!-- AC:END -->
