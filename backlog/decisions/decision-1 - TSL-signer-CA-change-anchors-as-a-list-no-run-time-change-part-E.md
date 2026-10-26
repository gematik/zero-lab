---
id: decision-1
title: 'TSL signer CA change: anchors as a list, no run-time change (part E)'
date: '2026-10-09 13:55'
status: accepted
---
## Context

spec/tsl-xmldsig part E (TSLSIG-061 – 068) describes how a TSL signer CA announced in the TSL becomes active at its StatusStartingTime, with a fallback through roots.json. Implementing it needs persisted announcements re-verified on load, a roots.json path with its own profile, age and OCSP checks, and signed test TSLs.

## Decision

Not implemented; judged too complex (2026-10-03). TrustConfig::tsl_signer_anchors is a list. A TSLServiceCertChange the TSL announces is reported as the warning tsl_anchor_announced, and a ti-pki release adds the new CA to anchors::TSL_SIGNER_CAS_*.

## Consequences

gematik changes the TSL signer CA rarely and announces it weeks ahead; GEM.TSL-CA3 runs until 2028-05-25. An installation follows a change only with a new release. Recorded in docs/development.md, Known compromises. Revisit with TASK-8 if that is no longer acceptable.
