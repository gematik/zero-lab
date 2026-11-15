---
id: TASK-323
title: >-
  go: encoding/json/v2 in every module; the Go profile names it for rule 28's
  JSON checks
status: In Progress
assignee: []
created_date: '2026-11-15T07:36:00Z'
updated_date: '2026-11-15T14:51:00Z'
labels: []
dependencies: []
ordinal: 338000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Go 1.27 has encoding/json/v2, whose defaults are what servers.md rule 28 asks of a JSON body and v1 does not do: a member twice is refused (v1 keeps the last), invalid UTF-8 is refused (v1 replaces it), names match only as written (v1 matches without regard to case), and UnmarshalRead refuses anything after the value. go/docs/design.md still prescribes encoding/json with DisallowUnknownFields plus a duplicate-key check of our own.

Found from zeta-pdp-go (its TASK-95, which moved its three modules to v2): the zero-lab modules it imports still read with v1, so a DPoP proof whose payload has a claim twice passes go/dpop, and the same holds for go/nonce, go/oidf, go/openid, go/idpd and the rest (about 60 non-test files import encoding/json; modules are on go 1.26 to 1.27.0).

What moving showed, for whoever does it here:
- omitempty no longer omits a zero number or false; such fields need omitzero.
- a nil slice or map is written [] or {} (was null); json.FormatNilSliceAsNull keeps the old form where a wire format needs it.
- map members are not sorted unless json.Deterministic(true): needed wherever output is hashed, signed or compared (ETags, thumbprints, golden files).
- time.Duration has no encoding and makes Marshal fail; a handler that ignores the error of MarshalWrite then sends an empty 200.
- json.RawMessage becomes jsontext.Value; json.Number is gone; Decoder/Encoder become UnmarshalRead/MarshalWrite.
- jsontext.Value.Canonicalize is RFC 8785, in place of an own canonicalization.
- <, > and & are no longer escaped; Encode's trailing line feed is gone.
The JOSE library keeps its own JSON reader; what it parses (JWS headers) is outside this.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 go/docs/design.md prescribes encoding/json/v2 (RejectUnknownMembers where the format is ours, Deterministic where output is hashed or compared) and drops the own duplicate-key check
- [x] #2 Each module's fuzz seeds have a member twice, a name in another case and invalid UTF-8, and the readers refuse them
- [x] #3 No module but go/pdp imports encoding/json v1 (go/pdp is replaced by zeta-pdp-go and left as it is); every module is on go 1.27
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
From the final review of TASK-315: the hosts still re-read the verified ID token with v1 through openid.TokenResponse.Claims (pdp nonce check and introspection, pep sess.Identity), while oidf judged the same payload with v2. They should take oidf's ExchangeIdentity / Identity instead.

2026-11-15: started on branch feat/json-v2, with TASK-332. go/pdp stays on v1: zeta-pdp-go replaces it.

feat/json-v2 at 8c7d770b: all modules but go/pdp on encoding/json/v2 and go 1.27.0; review fixed (epa non-UTF-8 error bodies, rd UTF-8, dpop panic); full just check green. Open before merge: epa HITL against RU for exact member names (maintainer to run or waive).
<!-- SECTION:NOTES:END -->
