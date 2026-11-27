---
id: TASK-448
title: >-
  tipki, ti-pki: a nonQES certificate's OCSP response is valid for an hour after
  producedAt (A_23225), not 37.5 s
status: To Do
assignee: []
created_date: '2026-11-27 11:47'
labels:
  - go
  - ti-pki
  - spec
dependencies: []
priority: high
ordinal: 457000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by zeta-authserver-go TASK-205 (2026-11-27): on zeta-go.t20r.cloud every SM(C)-B was refused for ten minutes with 'OCSP response is 50 s old, more than the 37 s allowed' while the node's clock was synchronized (chrony 0.3 us): the reference environment's responder signed fresh responses with a clock about 50 s behind.

go/tipki takes DefaultMaxResponseAge = DefaultClockTolerance (37.5 s, ocsp.go) and refuses a response whose producedAt is older (outsideWindow); rust ti-pki defaults DEFAULT_MAX_RESPONSE_AGE to the same. gemSpec_PKI V2.28.0 does not ask for that:
- GS-A_5215 makes 37.5 s the tolerance within which producedAt, thisUpdate and nextUpdate MUST be accepted in TUC_PKI_006 step 6; it does not ask to refuse beyond it, and its product types do not include ZT_Cluster.
- A_23225 (product types include ZT_Cluster, IDP-D, eRp_FD, Aktensystem_ePA, PoPP_Service, ...) defines for nonQES certificates: a revocation response is valid in time when s - D <= producedAt <= s + 5 min, D one hour by default (longer where an application's specification says so); valid responses MUST be cached and reused instead of asked anew; the OCSP-Graceperiod of TUC_PKI_006 is ignored, and the consistency check of step 6 (the times of GS-A_5215) is not done for OCSP responses in this context.
https://gemspec.gematik.de/docs/gemSpec/gemSpec_PKI/gemSpec_PKI_V2.28.0/#A_23225
https://gemspec.gematik.de/docs/gemSpec/gemSpec_PKI/gemSpec_PKI_V2.28.0/#GS-A_5215

QES certificates and the TSL signer's OCSP may keep a stricter check; which rule applies follows the certificate's profile, which tipki knows (TASK-175).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 For a nonQES certificate tipki and ti-pki accept a response whose producedAt lies up to D in the past (default one hour, configurable) and up to five minutes in the future, and refuse one outside that window
- [ ] #2 A response valid in time is taken from the cache, not asked anew, for the same certificate (A_23225 2.); a test shows a second check within the hour makes no request
- [ ] #3 The times of GS-A_5215 are not checked for a nonQES certificate's OCSP response; tests with responses 50 s and 59 min old (accepted) and 61 min old and 6 min ahead (refused), each citing A_23225
<!-- AC:END -->
