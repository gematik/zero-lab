---
id: TASK-98.1
title: ti profile server check in go/tipki
status: Done
assignee: []
created_date: '2026-11-06T14:01:00Z'
updated_date: '2026-11-06T18:25:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 244000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ServerCheck in go/tipki following ti_pki::tls (TLSV rules of the ti profile): validator without revocation, signature algorithm, name (SAN/CN, wildcards), OCSP stapled within the grace else the responder. Passes the ti cases of spec/pki-validation/testdata.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the ti corpus cases pass with the codes the manifest expects
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
e41c4f97 on spec/go-pki-validation: go/tipki/tls.go ServerCheck{Store, OCSPGrace}, NewServerCheck, Verify(ctx, chain, host, stapled, now, responder) Verdict, VerdictCode, NamesHost, DNSNameMatches; Verdict adds NextUpdate for TLSV-050/051 reuse. All 23 ti corpus cases pass. Deviations: nil responder gives ocsp_unavailable; zoned IPv6 hosts never match. Order question filed as TASK-233.
<!-- SECTION:NOTES:END -->
