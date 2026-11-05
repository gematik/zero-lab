---
id: TASK-185
title: 'Go: secrets and session data in logs'
status: In Progress
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-05T18:57:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 195000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pdp authorize.go logs authnSession and authzSession at Info including the PKCE verifier, nonce and state, and start.go logs the pdp struct at Debug. oauth/oidc client.go logs client_secret and code at Debug. oidf client.go logs PAR state and nonce at Info, and relying_party.go logs a config that may hold an inline private key. epa entitlements.go logs the signed entitlement JWT, and zero-epa config prints passwords and the HMAC key. oauth/oidc secret_string.go says secrets are not marshaled but marshals them. servers.md rule 5. TASK-177 covers gemidp alone. Reported while clearing lint (TASK-86); not each one reproduced.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 No secret, token, verifier or key reaches a log or stdout in these paths, and SecretString does what its comment says
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed outside epa, with capture tests. Open for go/epa, which stays as it is for now.

go/epa: the entitlement body (the signed JWT), request headers, the authorization URI and the code's redirect URL are out of the log; zero-epa config prints authn_p12_password and vsdm_hmac_key_hex redacted. KVNRs are out of the proxy's server log; the probe command, run by hand, still shows the one it was given.
<!-- SECTION:NOTES:END -->
