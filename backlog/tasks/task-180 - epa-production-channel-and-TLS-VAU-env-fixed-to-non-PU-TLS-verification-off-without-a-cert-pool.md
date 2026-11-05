---
id: TASK-180
title: >-
  epa: production channel and TLS: VAU env fixed to non-PU, TLS verification off
  without a cert pool
status: Done
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-05T19:32:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 190000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OpenChannelVerified ignores its env argument and sets EnvNonPU (vau/key_exchange.go), and session.go passes EnvNonPU for prod too, so a production channel would carry the wrong environment byte. session_manager.go falls back to WithInsecureSkipVerify whenever CertPool is nil, which holds for any proxy from a config file (CertPool is yaml:"-"); probe.go always passes it; ProxyConfig has no production check. Also Init uses a test-data HCV for every insurant (proxy.go CalculateHCV). Found by gosec G402 (TASK-86) and reading.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A production channel carries the production byte, TLS is verified unless a non-production configuration says otherwise, the HCV is the insurant's, and the nolint line naming this task is gone
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done: a production channel carries the production environment byte (OpenChannelVerified used to ignore env). Open, needing the maintainer: TLS verification (the aggregators use TI component CA certificates, GEM.KOMP-CA55 TEST-ONLY outside production, so verifying needs TI roots, see TASK-98) and the HCV (Init derives it from fixed test data for every insurant).

Maintainer, 2026-11-05: TLS verification waits for TASK-98. The fixed test-data HCV stays: zero-epa is not for production.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed after the production byte. TLS verification of the aggregators moved to TASK-98, which gives epa the TI-PKI profile. The fixed test-data HCV stays, as zero-epa is not for production.
<!-- SECTION:FINAL_SUMMARY:END -->
