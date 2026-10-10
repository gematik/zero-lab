---
id: TASK-25
title: >-
  Go footprint: archive ti and kon, module status table, remove
  oauth/oauth2client
status: To Do
assignee: []
created_date: '2026-10-10 15:04'
labels:
  - go
dependencies: []
priority: medium
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred from the epa plan (doc-1). go/ti and go/kon have no commits after their last tags (go/ti/v0.23.4, go/kon/v0.21.4), so those are the archive points. Follow 9b4054a: drop ./ti and ./kon from go/go.work, delete both directories, remove build-ti from go/Justfile, replace the go install .../go/ti@... examples in go/docs/development.md and ReleaseNotes.md with zero-pdp, fix the dead ./docs/development.md link in the root README and ReleaseNotes, update rust/ti-cli/AGENTS.md (.kon files shared with the Go ti). Delete the unused go/oauth/oauth2client stub. Add a Module status section to go/docs/development.md: active (pdp, pep, bff, zaddy, kv, nonce, dpop, oauth/oidc, oidf, gemidp, epa, metsubushi), frozen (brainpool; gempki and pkcs12 kept for epa only), archived (asl, libzero, ti, kon with tags) and the archive procedure.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 cd go && just check green; just build produces zero-epa, zero-pdp, zero-caddy
- [ ] #2 grep for go/ti, go/kon, build-ti, oauth2client outside the status table and release notes is empty; the archive tags still exist
- [ ] #3 all links in README.md, ReleaseNotes.md, go/docs/development.md resolve
<!-- AC:END -->
