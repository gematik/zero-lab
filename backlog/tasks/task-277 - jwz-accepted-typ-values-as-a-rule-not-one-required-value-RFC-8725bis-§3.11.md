---
id: TASK-277
title: 'jwz: accepted typ values as a rule, not one required value (RFC 8725bis §3.11)'
status: Done
assignee: []
created_date: '2026-11-08T15:20:00Z'
updated_date: '2026-11-19 08:55'
labels:
  - jwz
dependencies: []
priority: low
ordinal: 293000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258. Policy::typ is one required value. draft-ietf-oauth-rfc8725bis-10 §3.11 describes verifiers that accept a set of explicit types, or require a match only when typ is present. A small rule type in place of Option<String> would express it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Policy states the accepted typ values and whether typ is required; the existing behaviour is one case of it
- [x] #2 tests named after the draft section; the draft revision pinned
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Policy::typ is TypRule: Any, Required(values), IfPresent(values); TypRule::required(typ) is the former Some(typ). Draft pinned: draft-ietf-oauth-rfc8725bis-10 (2026-08-21), §3.11, read on 2026-11-19: it has the retrofit rule (a typ that is present must be the expected one, which breaks no producer) and speaks of acceptable typ values in the plural; it has no sentence on a set of types, so several values are this crate's reading. Test draft_ietf_oauth_rfc8725bis_10_3_11_a_typ_that_is_present_must_be_an_accepted_one; the existing rfc_8725_3_11 tests use TypRule::required. Guide and ADR 0001 updated.

2026-11-19, maintainer: everything explicit. TypRule::Required and IfPresent name one typ, not a list; TypRule::required/if_present constructors removed. A host that takes two kinds of token has a profile for each (RFC 8725 §3.12). Test renamed draft_ietf_oauth_rfc8725bis_10_3_11_a_typ_that_is_present_must_be_the_expected_one.
<!-- SECTION:NOTES:END -->
