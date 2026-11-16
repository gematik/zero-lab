---
id: TASK-337
title: 'Go: errors and logs that quote a peer''s answer or the input (rule 14)'
status: Done
assignee: []
created_date: '2026-11-15T14:33:00Z'
updated_date: '2026-11-16T23:12:00Z'
labels: []
dependencies: []
ordinal: 352000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found while moving to encoding/json/v2 (TASK-323, 2026-11-15); all predate it. servers.md rule 14 forbids attacker input or a peer's body in errors and logs. Places: epa parseHTTPError and GetStatus quote the Aktensystem's error body (now only bounded); pep/proxy backend_pdp.go "token endpoint %d: %s" passes the authorization server's body into errors and logs; brainpool josebp "unsupported key type: %s"; tipki "unknown source %q"; and every place that wraps a json/v2 decoder error with %w, whose message names the member. Each becomes a reason that names the field or the status, never the value.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 None of the places listed quotes a peer's body or the input in an error or log; a test per place shows the refused value is not in the error
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Errors in brainpool, tipki, epa (incl. vau), pep, pep/proxy, openid and idpd name the field or status and a fixed reason; decoder errors stay unwrappable for errors.Is/As. The ePA proxy passes on only the 26 error codes the ePA-Basic 3.1.3 interfaces register, errorDetail never. Every TestServerRule14_ asserts the reason. Full just check and live ePA connect (enforce) passed. Remaining places: TASK-363.
<!-- SECTION:FINAL_SUMMARY:END -->
