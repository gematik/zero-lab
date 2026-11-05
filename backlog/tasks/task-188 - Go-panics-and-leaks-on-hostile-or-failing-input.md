---
id: TASK-188
title: 'Go: panics and leaks on hostile or failing input'
status: In Progress
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-05T18:57:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 198000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
epa vau channel.go Decrypt and server.go DecryptNestedRequestData slice ciphertext[:12] after only a 43-byte length check. OpenChannelVerified calls log.Fatalf on bad server data. epa proxy forward loops never close resp.Body. oidf ServeSignedJwks has no return after http.Error; FetchEntityStatement dereferences Jwks without a nil check; FetchSignedJwks leaks the body. oauth/oidc TokenResponse.Claims panics on a token with no dot, and ExchangeForIdentity never closes the body. Reported while clearing lint (TASK-86); not each one reproduced.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each returns an error with a test or fuzz target, and none exits or panics
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed outside epa. Open for go/epa.

go/epa: Decrypt on both sides refuses a message shorter than header, IV and tag; the handshake returns errors where it called log.Fatalf (9 places); the forwarding closes response bodies. Tests: short messages, and Message2 damaged at 100 positions never exits the process.
<!-- SECTION:NOTES:END -->
