---
id: TASK-285
title: >-
  READMEs: a short licence line in the crates; ti-pki's README brought up to
  date
status: Done
assignee: []
created_date: '2026-11-10T18:40:00Z'
updated_date: '2026-11-10T19:52:00Z'
labels:
  - docs
  - rust
dependencies: []
priority: medium
ordinal: 301000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback: every crate README repeats the licence and gematik's disclaimer in full; maintainer: a short line linking the root README everywhere, jwz included; only the root README keeps both. rust/ti-pki/README.md is out of date (a v0.1.0 tag that does not exist, statements before TASK-270) and its main example is hot reload instead of validating a certificate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 every README under rust/ carries one licence line linking the root README; the root README keeps License and Disclaimer
- [x] #2 ti-pki's README leads with validating a certificate (as the tested lib.rs quick start), then production, offline, TLS, loading, and hot reload last; stale statements fixed
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
All twelve READMEs under rust/ carry one licence line; the root README keeps License and Disclaimer. ti-pki's README rewritten: the tested quick start first, then configuration, production, offline, TLS servers, loading, hot reload last; the non-existent v0.1.0 tag replaced by 'pin a commit'.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Every README under rust/ carries one licence line linking the root README, which keeps License and Disclaimer; ti-pki's README leads with validating a certificate and has hot reload last.
<!-- SECTION:FINAL_SUMMARY:END -->
