---
id: TASK-363
title: 'Go: the remaining peer data in errors and logs (rule 14), after TASK-337'
status: Done
assignee: []
created_date: '2026-11-16T23:01:00Z'
updated_date: '2026-11-22 15:18'
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
- [x] #1 None of the places listed puts a certificate name, TSL value, key attribute, peer identifier, path or decrypted content into an error or log; each with a test
- [x] #2 idpd's Error names a registered OAuth error code as pep/proxy does
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: the epa places (vau/key_exchange.go, proxy.go, vau/channel.go, vau/server.go) are left out: zero-epa is not for production (maintainer, TASK-362).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
No error in tipki, idpd or pep quotes peer data any more: tipki's chain errors name no certificate, its TSL errors quote no element value or service name; idpd's certificate refusal lists the findings' codes, not their messages (which name certificates); pep refuses a key's use without quoting it. idpd's Error names an error code RFC 6749 registers, as pep/proxy does, and nothing else. Tests: TestServerRule14_AChainErrorNamesNoCertificate, TestServerRule14_ATSLValueIsNotQuoted (tipki), TestServerRule14_AnIDPDienstErrorNamesARegisteredCodeOnly (idpd), TestServerRule14_AKeysUseIsNotQuoted (pep). zero-epa's places left out, as it is not for production.
<!-- SECTION:FINAL_SUMMARY:END -->
