---
id: TASK-355
title: 'epa: a forwarded request keeps its framing inside the VAU'
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-18T20:05:00Z'
labels: []
dependencies: []
priority: high
ordinal: 370000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`forwardToVAU` (`epa/proxy.go:434-484`) builds the inner request from the client's body and headers, and `vau.Channel.EncryptRequest` serialises it with `httputil.DumpRequest`. For a chunked request the inner message has a body but neither `Content-Length` nor `Transfer-Encoding` (verified), so the Aktensystem reads the body as whatever follows: a smuggled second request inside the VAU or a lost body. servers.md rule 28, "Headers" (request smuggling, RFC 9112 §6.3). Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the inner request always carries the exact `Content-Length` of the body it is sent with, and client `Content-Length`/`Transfer-Encoding`/hop-by-hop headers are never copied into it.
- [x] #2 a test sends a chunked request through the proxy to a fake VAU and checks the inner message's framing and body.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Branch fix/rule28-gaps, aa159bc6. forwardToVAU reads the body and builds the inner request from it, so ContentLength is exact; copyAndPrepareHeaders drops Content-Length, Transfer-Encoding and the hop-by-hop headers, and those named in Connection. vau.Channel.EncryptRequest refuses an unknown length, Transfer-Encoding, or a body with ContentLength 0 (ErrRequestFraming) and sets Content-Length itself, since httputil.DumpRequest writes it only from the header map: that was the root cause. vau.Server (test VAU) has an Inner hook. Tests: TestServerRule28_AChunkedRequestIsFramedByItsLengthInsideTheVAU (chunked through the proxy to the test VAU; parses the inner message, exact length, no bytes after it, no hop-by-hop headers), TestServerRule28_TheVAUChannelRefusesARequestWithoutAKnownLength. The body read is not bounded yet: the limit is TASK-357's (limits before work).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged in c92d0f8d (fix/rule28-gaps). The proxy reads the body and forwards it with its length; hop-by-hop headers and those Connection names are dropped. The VAU channel refuses a request without a known length (ErrRequestFraming) and writes Content-Length into the inner request. Tests: TestServerRule28_AChunkedRequestIsFramedByItsLengthInsideTheVAU, TestServerRule28_TheVAUChannelRefusesARequestWithoutAKnownLength. The body read is unbounded; the limit is TASK-357's. epa not yet released.
<!-- SECTION:FINAL_SUMMARY:END -->
