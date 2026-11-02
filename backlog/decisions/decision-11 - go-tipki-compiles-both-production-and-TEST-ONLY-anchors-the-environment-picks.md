---
id: decision-11
title: go/tipki compiles both production and TEST-ONLY anchors; the environment picks
date: '2026-11-02T16:07:00Z'
status: accepted
---

## Context

zero-pdp and zero-pep now verify the IDP-Dienst's certificates through go/tipki, so a binary needs the anchors of the environment it talks to. go/tipki held the TEST-ONLY anchors under a build tag, which would have meant separate images per tier. Mounting them as files was also weighed.

## Decision

Maintainer, 2026-11-02: one image. go/tipki compiles in both GEM.RCA7 and GEM.TSL-CA3 and the TEST-ONLY GEM.RCA7 and GEM.TSL-CA28, without a build tag. The environment a host names picks one set: production trusts only the production anchors, test and reference only the TEST-ONLY pair. Nothing is mounted.

## Consequences

- One image serves every environment.
- The environment now decides trust, so it must be named: go/gemidp refuses a missing or unknown one rather than defaulting to any set (IDPV-006). A production deployment that names `ref` trusts the TEST-ONLY anchors, and then production certificates fail against them.
- A production binary holds TEST-ONLY material it does not use, which the build tag used to rule out.
- Rust keeps its `dangerous-nonprod` feature (decision-1); the two differ here until decided otherwise.
