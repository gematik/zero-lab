---
id: TASK-292
title: 'oidf: metadata policy is ignored'
status: Done
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-22 12:13'
labels: []
dependencies: []
ordinal: 308000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No metadata_policy of a superior statement is applied to a subject's metadata; the name does not occur in go/oidf. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 metadata_policy and metadata_policy_crit are not read; the decision and the specification check are recorded beside parseEntityStatement
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22, checked against the specifications (maintainer's request): gemSpec_IDP_FedMaster 1.4.3, gemSpec_IDP_Sek 3.3.0 and gemSpec_IDP_FD 2.2.0 never mention metadata_policy or metadata_policy_crit (nor any policy). Only gemKPT_TI-Föderation 1.0.0, a non-binding concept, names them, in its validation walkthroughs (chapter 10.3), among the claims its example statements do not contain, so the OpenID Federation 1.1 steps for them do not apply there. So the TI federation sets no metadata policy today and nothing requires oidf to apply one. Proposed instead of implementing OpenID Federation 1.1 §6.1: fail closed, i.e. refuse a subordinate statement of the master that carries metadata_policy or metadata_policy_crit, so that a policy appearing later stops the login instead of being ignored; implement the operators only if the master starts to use them.

2026-11-22, gemSpec_ZETA checked as well: release 1.3.2 and the draft 2.0.0_CC (Draft_ZETA_26_2, 2026-07-09, not binding) never mention metadata_policy or metadata_policy_crit. ZETA describes the guard's trust in an IDP as one level, as oidf builds it: the guard asks the federation master for the IDP's statement (subject idp_iss), validates that chain and imports the IDP's signing key and OP metadata (PAR, authorization and token endpoint); the IDP checks the guard the same way at the master (subject client_id). ZETA cites OpenID Federation 1.0. The finding stands: no policy to apply in the TI today; fail closed proposed.

2026-11-22: a refusal of statements with a policy was built (fail closed) and dropped again by the maintainer's decision: ignore the policy entirely, as oidf always did. Accepted deviation from OpenID Federation 1.0 Section 6.1: should the master ever set a policy, oidf takes the provider's metadata as the provider states it. A change of gemSpec_IDP_FedMaster that introduces policies reopens this.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
No TI specification sets a metadata policy (gemSpec_IDP_FedMaster 1.4.3, IDP_Sek 3.3.0, IDP_FD 2.2.0, ZETA 1.3.2 and draft 2.0.0_CC; only the non-binding gemKPT_TI-Föderation 1.0.0 names it, as absent). By the maintainer's decision oidf does not read metadata_policy or metadata_policy_crit at all; the doc comment of parseEntityStatement says why. No behaviour change.
<!-- SECTION:FINAL_SUMMARY:END -->
