---
id: TASK-363
title: 'Go: the remaining peer data in errors and logs (rule 14), after TASK-337'
status: To Do
assignee: []
created_date: '2026-11-16T23:01:00Z'
labels: []
dependencies: []
priority: medium
ordinal: 378000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the review of TASK-337 (2026-11-17), outside its scope: tipki/chain.go ~60,66 and idpd/trust.go ~116 put the certificate CN into errors (for an HBA a person's name); tipki/tsl.go ~553,566 quote TSL element values and service names; pep/token.go ~133 quotes key.Use from a key set; epa/vau/key_exchange.go ~178 (VAU-CID) and ~599 (CertData) log peer data at debug; epa/proxy.go ~373,465,477 and vau/channel.go ~206,211 log the request path or URL; epa/vau/server.go ~393 logs the whole decrypted inner response at Info (a test VAU, but in a non-test file); idpd's Error hides even registered OAuth error codes, which pep/proxy passes. servers.md rule 14.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 None of the places listed puts a certificate name, TSL value, key attribute, peer identifier, path or decrypted content into an error or log; each with a test
- [ ] #2 idpd's Error names a registered OAuth error code as pep/proxy does
<!-- AC:END -->
