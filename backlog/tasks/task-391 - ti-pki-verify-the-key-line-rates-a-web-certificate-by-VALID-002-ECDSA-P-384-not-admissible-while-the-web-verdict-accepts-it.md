---
id: TASK-391
title: >-
  ti pki verify: the key line rates a web certificate by VALID-002 (ECDSA P-384
  not admissible) while the web verdict accepts it
status: To Do
assignee: []
created_date: '2026-11-19 12:42'
labels:
  - rust
  - pki
  - cli
dependencies: []
references:
  - spec/pki-validation/README.md
  - rust/ti-pki/src/key.rs
  - rust/ti-pki/src/model/certificate.rs
  - rust/ti-cli/src/commands/inspect.rs
priority: medium
ordinal: 404000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed 2026-11-19 with ti-cli 0.6.2 (rust/ti-cli at 9117b2c8): `ti pki verify --connect dienst.vsdd2.ru.service-ti.de` shows an end entity of the Web-PKI (GeoTrust G5 TLS ECC P-384 SHA384 2022 CA2, policy 2.23.140.1.2.1, `TI type not detected`) with

```
Key
  algorithm      ECDSA P-384 not admissible
...
TLS server verdict
  result         VALID
  profile        web (auto: not a TI certificate)
```

The verdict is right: the web profile admits an end entity key of ECDSA P-256 or P-384, or RSA of at least 3000 bits, and RSA 2048 to 2999 with the warning `key_phased_out` (spec/pki-validation TLSV-041, A_28976). The key line is not: it comes from `ti_pki::key::classify_key` (rust/ti-pki/src/model/certificate.rs:128), which applies VALID-002, the gemSpec_Krypt tables for TI certificates (brainpoolP256r1 and P-256 only), to every certificate, whatever profile it falls under. So one screen says a key is not admissible and the connection valid.

The maintainer states (2026-11-19) that P-384 and higher, and RSA of 3000 bits and higher, are admissible. TLSV-041 lists P-256 and P-384 for the web profile; whether P-521 ("higher") is admissible is to be checked against A_28976 and gemSpec_Krypt before the rule changes.

Not checked: ti-client's inspect path (rust/ti-client/src/pki/inspect.rs:244, signature.rs:92), which call the same function, and Go's go/tipki, which has no CLI that prints the line.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The key line of a certificate that is not a TI certificate is rated by the web profile's rule (TLSV-041, TLSV-042 for a CA), a TI certificate's by VALID-002, and the line says which rule it applied
- [ ] #2 A test named after TLSV-041 shows an ECDSA P-384 web end entity as admissible and an RSA 2048 one as phased out, in the key line and in the verdict alike
- [ ] #3 Whether P-521 is admissible for the web profile is answered from A_28976 / gemSpec_Krypt and recorded in spec/pki-validation
<!-- AC:END -->
