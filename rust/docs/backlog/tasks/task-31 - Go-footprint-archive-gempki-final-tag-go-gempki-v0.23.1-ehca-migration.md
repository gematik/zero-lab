---
id: TASK-31
title: 'Go footprint: archive gempki (final tag go/gempki/v0.23.1), ehca migration'
status: In Progress
assignee: []
created_date: '2026-10-11 11:20'
updated_date: '2026-10-11 11:25'
labels:
  - go
  - gempki
dependencies: []
priority: medium
ordinal: 29000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/gempki (6.5k lines: certificates, types, admission, OID tables, roots, TSL, OCSP, path validation) is unmaintained; its Rust successor is ti-pki. No module in the zero-lab Go workspace imports it any more (2026-10-11). Its one consumer is ehca-go (github.com/gematik/ehca, pins v0.22.0), which uses only the conformance part: ParseCertificate, DetectCertificateType, CertificateType, ParseAdmissionStatement/AdmissionStatement/ErrNoAdmissionStatement, CheckRoleOID, ValidationError, and ~17 gempki/oid constants with Lookup/Format; none of roots, TSL, OCSP or validation. Archive like go/ti and go/kon: tag the two commits since v0.23.0 as the final go/gempki/v0.23.1, remove ./gempki from go.work and the tree, move it to Archived in go/docs/development.md, update ReleaseNotes. The tag keeps it go-gettable, so ehca keeps building and migrates at its own pace. brainpool and pkcs12 stay (Frozen). Proposal for ehca (theirs to decide): (1) conformance checks move into an ehca-internal package: the OID constants it needs named after their gemSpec_OID references (decision-5, e.g. INST_PRAXIS_ARZT instead of InstArztpraxis), admission statement parsing, type detection from certificatePolicies, the role check; certificate parsing stays on go/brainpool; (2) the planned ehca x509 validate (chain, TSL, OCSP) calls the Rust ti as a subprocess (ti pki verify --format json, profile hci-aut etc.), as go/epa does; (3) ehca's CLAUDE.md stops pointing at the removed go/ti and at go/gempki.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go/gempki/v0.23.1 tagged and pushed; ./gempki removed from go.work and the tree; go vet and tests green for every remaining module
- [x] #2 go/docs/development.md lists gempki as Archived with its tag; ReleaseNotes says so; nothing in the repo refers to go/gempki as current
- [ ] #3 ehca owners have the migration proposal (issue or MR in ehca-go); ehca keeps building on the tag meanwhile
<!-- AC:END -->
