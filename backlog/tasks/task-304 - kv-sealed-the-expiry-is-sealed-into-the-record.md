---
id: TASK-304
title: 'kv sealed: the expiry is sealed into the record'
status: To Do
assignee: []
created_date: '2026-11-13T06:39:00Z'
labels: []
dependencies: []
ordinal: 319000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
NewSealed binds a record to its key and purpose, but when it ends is a column of the store below. Who can write to the database can make a record outlive what the server meant, or put back a record that was deleted, for as long as they like. Seal the expiry with the record (in the associated data or the sealed header), and let Get and Take answer ErrIntegrity, or absent, for a record past its sealed expiry whatever the store says. This bounds extending and putting back to the record's own lifetime; it cannot detect deletion. Needs the clock of the sealed store as a parameter. Found by zeta-pdp-go (integrity review of its store, 2026-11-13).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A record whose stored expiry was extended does not open after its sealed expiry
- [ ] #2 A record without expiry (ttl 0) still opens
- [ ] #3 Records sealed before the change still open, or the format version says they do not and the release notes say so
<!-- AC:END -->
