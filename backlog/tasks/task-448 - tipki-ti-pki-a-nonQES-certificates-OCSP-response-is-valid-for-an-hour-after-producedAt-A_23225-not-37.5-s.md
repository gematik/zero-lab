---
id: TASK-448
title: >-
  tipki, ti-pki: a nonQES certificate's OCSP response is valid for an hour after
  producedAt (A_23225), not 37.5 s
status: In Progress
assignee: []
created_date: 2026-11-27 11:47
updated_date: '2026-11-27T11:55:00Z'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Scope: go/tipki and rust ti-pki, same design in both; ti-client/ti-cli and the Go hosts follow.

1. Window by certificate (VerifyResponse / verify_response, online check only; stapled unchanged)
   - nonQES (default): A_23225, s - D <= producedAt <= s + 5 min. D = MaxResponseAge, default 1 h (DefaultMaxResponseAge, DEFAULT_MAX_RESPONSE_AGE). New constant for the 5 min (ResponseFutureTolerance). thisUpdate and nextUpdate are not checked (A_23225 4. and its explanation).
   - QES (C.CH.QES, C.HP.QES by DetectCertificateType): GS-A_5215 as today, 37.5 s on every side, thisUpdate and nextUpdate checked.
   - The rule follows from the certificate, no new switch for callers. A reason names the rule (A_23225 or GS-A_5215).
2. Cache (OCSPChecker; OcspChecker in memory and its ti-cache store)
   - good and revoked are reused until producedAt + D, no longer capped by nextUpdate; asked again only after that (A_23225 2. and 3.). The persistent entry carries the same end; read back, it is verified again as today.
   - unknown and errors stay uncached.
   - Expired entries are removed on every check, throttled, so an active checker never keeps one past 24 h (A_23225 5.).
   - QES results: cached as today (1 h, nextUpdate).
3. Callers
   - NewOCSPChecker users (idpd, zero-epa trust, epatest) get the new default without a change.
   - epa/vau sets MaxResponseAge 24 h explicitly; under A_23225 that is its D, and thisUpdate/nextUpdate are no longer checked there. Check against the VAU spec before release.
   - TLS stapling (ServerCheck.OCSPGrace, TUC_PKI_018 Tab_PKI_273) stays: A_23225 excludes stapled responses from its caching rule, A_30046 (7) checks them at the reference time.
   - ti pki verify --ocsp-max-age sets D; the report field max_response_age_ms shows D.
4. Tests and documents
   - Go and Rust: 50 s and 59 min old accepted; 61 min old and 6 min ahead refused; nonQES with a past nextUpdate accepted; QES 50 s old refused; each named after A_23225 or GS-A_5215.
   - Cache: a second check within D makes no request; after producedAt + D one request.
   - ti-pki traceability (TRACE_BLESS), tipki and ti-pki READMEs, release notes (behaviour change: minor versions of go/tipki and ti-pki), spec/tsl-xmldsig README line on GS-A_5215.
5. Release: go/tipki minor, then hosts (pep, idpd, epa) pinned; ti-pki with the next ti release; zeta-authserver-go told to bump.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decisions 2026-11-27: unknown stays uncached (deviation from A_23225's 'Sperrinformationen', documented: a new certificate's status may appear minutes later); epa/vau keeps the strict GS-A_5215 window with its 24 h, by naming the rule; a process that checks nothing does not sweep its in-memory cache (no timer in a sans-I/O core), documented, expired entries are never used.
<!-- SECTION:NOTES:END -->
