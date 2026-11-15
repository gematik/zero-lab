---
id: TASK-323
title: >-
  go: encoding/json/v2 in every module; the Go profile names it for rule 28's
  JSON checks
status: To Do
assignee: []
created_date: '2026-11-15T07:36:00Z'
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
- [ ] #1 go/docs/design.md prescribes encoding/json/v2 (RejectUnknownMembers where the format is ours, Deterministic where output is hashed or compared) and drops the own duplicate-key check
- [ ] #2 No module imports encoding/json v1; every module is on go 1.27
- [ ] #3 Each module's fuzz seeds have a member twice, a name in another case and invalid UTF-8, and the readers refuse them
<!-- AC:END -->
