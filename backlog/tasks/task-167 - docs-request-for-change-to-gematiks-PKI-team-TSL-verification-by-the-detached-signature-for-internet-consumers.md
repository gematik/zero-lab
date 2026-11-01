---
id: TASK-167
title: >-
  docs: request for change to gematik's PKI team, TSL verification by the
  detached signature for internet consumers
status: In Progress
assignee: []
created_date: '2026-11-01T16:11:00Z'
updated_date: '2026-11-01T16:44:00Z'
labels:
  - docs
  - pki
dependencies:
  - TASK-166
priority: medium
ordinal: 177000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Conditional on TASK-166's gate: new requirements for internet and TI 2.0 consumers are in gematik's pre-release pipeline and known to the maintainer. If they exclude verifying the TSL through .sig and .ocsp (gemSpec_TSL A_21177 to A_21181) in place of TUC_PKI_012, this task writes the request for change as backlog doc-3: the facts with requirement IDs; the proposal to extend gemSpec_PKI 8.2.6 / A_30044 so internet consumers MAY verify the TSL by the detached signature, to publish .sig and .ocsp on the HTTPS tsl.ti-dienste.de hosts as well, and to widen A_21175's Fallback fuer Konnektoren; the security argument (same signer, same anchor, same OCSP, TR-03111 signature format, hash compare unchanged, no XML canonicalization in the trust path); what stays (TUC_PKI_011, TUC_PKI_013, TSL time parameters, sequence numbers); open questions for the PKI team. German, with a one-paragraph English summary. If the requirements allow .sig verification, this task is closed as not needed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 doc-3 written and handed to the PKI team, or the task closed with the citation that makes it unnecessary
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01: doc-3 written on the maintainer's request ahead of the gate of TASK-166 (German, English summary on top): facts with requirement IDs, the proposal for gemSpec_PKI 8.2.6/A_30044 and gemSpec_TSL 6.3.1, the consumer's check sequence, the security argument, the transition, six questions for the PKI team. Handing it to the PKI team is the maintainer's step; if the pre-release requirements already allow the detached signature, the document becomes a note to the team instead of a request.
<!-- SECTION:NOTES:END -->
