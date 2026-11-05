---
id: TASK-159
title: >-
  ti-connector-client: base64ct in the generated Konnektor bindings, through
  wsdl2openapi
status: To Do
assignee: []
created_date: '2026-10-29T12:24:00Z'
updated_date: '2026-11-05T19:35:00Z'
labels:
  - rust
  - deps
  - connector
dependencies: []
priority: low
ordinal: 170000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
base64 0.23 is in ti-connector-client's core only for the Base64Binary type of the generated Konnektor bindings (src/api/soap.rs), and carries unsafe (unchecked UTF-8 of its own output); base64ct, already in every core's tree, does the same in constant time. Found by the unsafe inventory of TASK-156; until then base64 is an approved exception in rust/docs/unsafe-exceptions.md.

The code is not hand-written: wsdl2openapi's generator-rust writes it (src/emit/soap.rs, base64_binary()), and just generate-connector replaces src/api whole, so an edit of the generated file would not survive. The generator therefore emits base64ct (option A, chosen by the maintainer 2026-11-05): the same Base64Binary type, whitespace still stripped before decoding. base64ct refuses encodings with non-zero padding bits, which the recorded Konnektor responses have to confirm the Konnektor never sends. base64ct keeps its own row in unsafe-exceptions.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 wsdl2openapi's generator-rust emits base64ct for xs:base64Binary, with a test of whitespace and of refused non-canonical input, committed there
- [ ] #2 ti-connector-client regenerated with just generate-connector; base64 leaves its Cargo.toml and normal tree, and the recorded Konnektor responses still decode
- [ ] #3 base64's row leaves rust/docs/unsafe-exceptions.md and just unsafe-free passes
<!-- AC:END -->
