---
id: TASK-172
title: 'docs: .NET profile before the first code (uniffi-bindgen-cs)'
status: To Do
assignee: []
created_date: '2026-11-01T16:11:00Z'
labels:
  - docs
  - bindings
dependencies: []
priority: low
ordinal: 182000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
.NET joins Swift and Kotlin/Java as a client binding over the Rust core (maintainer, 2026-11-01; no .NET servers). docs/languages.md requires a profile before the first line of code: the twelve sections, which engines the binding exposes, how the host supplies transports, keys and clocks, how the shared spec corpora run through the binding, a workspace with just check, headers, a backlog label. The generator candidate is uniffi-bindgen-cs (NordSecurity, 0.x); its maturity and maintenance are evaluated against docs/conventions/dependencies.md before the profile commits to it, with P/Invoke of the Rust cdylib as the mechanism (the client-side equivalent of JNA).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 dotnet/docs/design.md and development.md written per docs/languages.md and reviewed like a design change
- [ ] #2 uniffi-bindgen-cs evaluated and the result recorded with the alternatives
<!-- AC:END -->
