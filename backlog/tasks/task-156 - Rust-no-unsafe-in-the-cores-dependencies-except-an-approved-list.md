---
id: TASK-156
title: 'Rust: no unsafe in the cores'' dependencies except an approved list'
status: To Do
assignee: []
created_date: '2026-10-29T06:33:00Z'
labels:
  - rust
  - security
  - dependencies
dependencies: []
priority: medium
ordinal: 164000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer rule (2026-10-29): a core crate carries no `unsafe`, also not through its dependencies. Crates that need `unsafe` (terminal, OS, FFI; e.g. rpassword for TASK-136) belong to the host (ti-cli), never to a core. Exceptions only on an approved list.

Today the workspace's `unsafe_code = "forbid"` (rust/docs/design.md) covers our own code only. The cores' normal trees (ti-pki, ti-connector-client without its ureq feature, ti-idpd, ti-directory, jwz, jwz-brainpool, ti-jwz, ti-xmldsig, ti-pkcs12, ti-report) already contain crates with `unsafe`, among them libc, getrandom, cpufeatures, zeroize, hybrid-array, memchr, aes, ghash/polyval, curve25519-dalek, crypto-bigint, ctutils/cmov. ti-types and ti-store are free of it.

Which crates are cores and which are hosts is decided in the task (ti-cli, ti-wasm's glue and adapter features such as ti-connector-client/ureq or ti-pki's reqwest adapter are hosts).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The rule is in the document it belongs to (rust/docs/design.md, the dependencies convention if it is language-independent), with what counts as a core, what as a host, and how an exception is approved
- [ ] #2 An inventory of every crate with `unsafe` in each core's normal dependency tree (all non-host features), with why it needs it (intrinsics, volatile zeroing, system calls, ...)
- [ ] #3 An exception list in the repository, each entry with crate, reason and approval date; the maintainer has approved the initial list
- [ ] #4 Crates that cannot be justified are replaced or moved behind a host feature, each as its own task
- [ ] #5 A just check recipe fails when a core's tree gains a crate with `unsafe` that is not on the list, also for a new version of a listed crate that is checked again; it is part of just check
- [ ] #6 The dependency proposal template for agents says whether a crate contains `unsafe` and in which crate it would land
<!-- AC:END -->
