---
id: TASK-391
title: >-
  ti pki verify: the key line rates a web certificate by VALID-002 (ECDSA P-384
  not admissible) while the web verdict accepts it
status: Done
assignee: []
created_date: '2026-11-19 12:42'
updated_date: '2026-11-23 01:51'
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
- [x] #1 The key line of a certificate that is not a TI certificate is rated by the web profile's rule (TLSV-041, TLSV-042 for a CA), a TI certificate's by VALID-002, and the line says which rule it applied
- [x] #2 A test named after TLSV-041 shows an ECDSA P-384 web end entity as admissible and an RSA 2048 one as phased out, in the key line and in the verdict alike
- [x] #3 Whether P-521 is admissible for the web profile is answered from A_28976 / gemSpec_Krypt and recorded in spec/pki-validation
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Rate the key line by the rule of the profile the certificate falls under: ti-tls exposes web::key_status (TLSV-041/042, the same judgement WebCheck::verify applies); ti-pki's model::Key carries the rule (VALID-002 by default); ti-client's describe_under/KeyRule picks it (verify --connect web: web; pki verify ti: VALID-002; pki inspect: VALID-002 when the certificate has a TI type or the input shows a TI environment, else web); the CLI prints the rule in the key line; JSON schemas gain key.rule. Answer P-521 from A_28976 and record it in spec/pki-validation.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: the same connection fails in the zeta CLI. ZETA SDK 2.0.1 checks the revocation of the chain as sent, and stops at the self-signed Root G5 the server sends. That is in zeta-backlog TASK-19.

2026-11-22: The web verdict already applied TLSV-041/042 (ti-tls web.rs); only the key line (ti_pki::model::Certificate::new -> classify_key, VALID-002) disagreed. Callers checked: ti-client pki/inspect.rs key_algorithm uses only the description (unchanged); pki/signature.rs rates the signer of a TI document signature, VALID-002 stays; connector cards and ti-connector-client use only the description. A TI CA carries no TI type, so pki inspect decides by the input's TI environment (pki verify's detection: embedded root, chain, markers); the corpus's web certificates carry TEST-ONLY and would read as TI there, real web certificates do not.

P-521 (AC #3): A_28976 (gemSpec_Krypt V2.51.0, https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.51.0/#A_28976) names no curves; it requires the 120-bit level per TR-02102-2 'Domainparameter und Schlüssellängen'. TR-02102-2 version 2026-01, section 3.6.1 Table 14 (ECDSA >= 250 bit, RSA >= 3000 bit) and 3.6.2 (brainpoolP256r1/384r1/512r1 recommended, secp256r1/secp384r1/secp521r1 where those are unavailable). So P-521 meets A_28976. A_16176-01 (ePA-internal non-TI keys) lists P-256, P-384 and brainpool, not P-521. The rule is not changed: A_28976 binds the provider, not what a client must accept, and the verifiers have no P-521 signature verification (WEB_CERTIFICATE_ALGORITHMS, WEB_SCHEMES); admitting it needs that first. Recorded in spec/pki-validation/README.md, 'Keys beyond the rules', referenced from TLSV-041/042.

Verification: cargo test (ti-client pki::inspect, ti-cli verify_tls_server) pass; just check-changed: fmt, clippy (both feature sets), doc pass; nextest 820/821, the one failure ti-cli::probe probes_protocols_catalog_instances_and_timeouts passes alone (timing under load, unrelated).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The key line of `ti pki verify` and `ti pki inspect` now names the rule it applied and follows the profile: a certificate judged under the TLS profile web (verify --connect, web) is rated by TLSV-041 (end entity) or TLSV-042 (CA) through ti_tls::web::key_status, the judgement the verdict applies; a TI certificate keeps VALID-002. pki inspect takes VALID-002 when the certificate has a TI type or the input shows a TI environment, the web rule otherwise. ti_pki::model::Key gains `rule` (JSON: key.rule, schemas of pki inspect, identity inspect and ti-wasm updated). Tests: ti-client tlsv_041_the_key_line_of_a_web_certificate_agrees_with_its_verdict (P-384 admissible, RSA 2048 phased out with key_phased_out, key line and verdict on the same corpus certificates), valid_002_a_ti_certificate_is_rated_by_the_ti_tables, ti-cli tlsv_041_the_key_line_names_the_web_rule. P-521: meets A_28976 (via TR-02102-2 2026-01 §3.6), not listed by A_16176-01; TLSV-041/042 stay at P-256/P-384 because the verifiers have no P-521 verification; recorded in spec/pki-validation 'Keys beyond the rules'.
<!-- SECTION:FINAL_SUMMARY:END -->
