---
id: TASK-356
title: >-
  epa: proxy routes declare methods, canonical paths, parameters and response
  headers
status: Done
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-22T10:13:00Z'
labels: []
dependencies:
  - TASK-360
priority: medium
ordinal: 371000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Six routes in `epa/proxy.go:322-335` have no method pattern; `{path...}` is used decoded, so `%3F`, `%23`, `%2e%2e` and `%2F` change the inner request (`proxy.go:434-451`) and `providerURL` repairs `..` (`proxy.go:404-414`); the query is forwarded raw; the insurant VAU route skips the KVNR check (`proxy.go:630-645`); upstream response headers are copied wholesale (`proxy.go:383, 475`). servers.md rule 28, "Method and path", "Parameters" and "Output". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each route accepts its declared methods only; a forwarded path with encoded separators, dot segments or characters outside its grammar, a repeated query key and an insurant ID outside the KVNR grammar get 400; only an allowlist of response headers is relayed.
- [x] #2 fuzz targets over the forwarded path/query handling and `providerURL` assert that the target stays on the provider and under its path.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, branch fix/epa-rule28 (dc3976f6, 33d80af4). Routes per method (GET POST PUT DELETE on the forwarding routes, GET elsewhere); the mux answers 405 with Allow; method-override headers are dropped. Proxy.ServeHTTP checks the path with httpguard.Path; the forwarded path is the rest of the escaped path (an encoded ? or # stays in the inner path), providerURL refuses a non-canonical path and checks the target stays under the base path. The query is parsed with the new httpguard.Query (repeated, malformed, ; separator, empty name, controls, invalid UTF-8 refused) and forwarded as encoded anew. The insurant VAU route checks the KVNR. Response headers: allowlist Content-Disposition, -Encoding, -Language, -Type, ETag, Last-Modified, Retry-After, X-Request-Id; Location is not relayed. Fuzz: FuzzProviderURL, FuzzForwardedTarget, httpguard FuzzQuery, 1 min each. Caveat: FHIR search uses repeated parameters for AND (date=ge..&date=le..); these now get 400 as the AC says. httpguard needs v0.2.0 tagged before epa's next tag.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged in bbf8921f (fix/epa-rule28). The proxy's routes take their declared methods only (405 with Allow), the path is checked as received and forwarded escaped, the query is parsed strictly with httpguard.Query and forwarded as checked, the insurant VAU route checks the KVNR, and only an allowlist of response headers is relayed. Fuzz targets FuzzProviderURL and FuzzForwardedTarget keep the target on the provider and under its path. Repeated query parameters, including FHIR AND searches, get 400. epa needs httpguard v0.2.0 tagged and synced before its own tag.
<!-- SECTION:FINAL_SUMMARY:END -->
