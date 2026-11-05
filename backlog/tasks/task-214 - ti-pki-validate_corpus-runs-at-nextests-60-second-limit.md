---
id: TASK-214
title: 'ti-pki: validate_corpus runs at nextest''s 60-second limit'
status: Done
assignee: []
created_date: '2026-11-05T18:12:00Z'
updated_date: '2026-11-05T19:47:00Z'
labels:
  - ti-pki
  - testing
dependencies: []
priority: medium
ordinal: 221000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The test valid_001_the_corpus_is_what_ti_pki_says in rust/ti-pki/tests/validate_corpus.rs takes 50 to 58 seconds in a debug build, against the 60-second limit of rust/.config/nextest.toml. It timed out in 2 of 5 just check runs on 2026-11-05, with a load average of about 18 to 25 from other work on the machine, and passed in the others. A timeout fails just check and skips the recipes after test. No change on the branches involved touched the test. Find out where the time goes, then make it fast enough to stay well inside the limit without weakening what it proves. Raising the limit is not the fix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The cause of the test's run time is known and recorded in the task
- [x] #2 The test stays well inside nextest's limit on a loaded machine, with the limit unchanged
- [x] #3 The test still proves the whole corpus: no case is dropped or skipped to save time
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Cause, measured 2026-11-05 on the unchanged test (6,104 matrix cases, each a chain validation with real signatures): built as debug it took 49.8 s; with all dependencies at opt-level 3, 14.1 s; with everything optimized, 4.5 s; with a hand-picked list of crypto crates, 17.6 s. Most of the time was the unoptimized curve and RSA arithmetic of the dependencies. Fix: [profile.dev.package."*"] opt-level = 2 in rust/Cargo.toml, 13.0 s at a load average of about 9; the workspace's own crates stay unoptimized for debugging, the limit and the test are unchanged. ti-pki's whole nextest run: 306 tests in 15.9 s.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Dependencies are built optimized in debug and test builds, so validate_corpus takes about 13 s instead of 50 s, with the test and nextest's limit unchanged.
<!-- SECTION:FINAL_SUMMARY:END -->
