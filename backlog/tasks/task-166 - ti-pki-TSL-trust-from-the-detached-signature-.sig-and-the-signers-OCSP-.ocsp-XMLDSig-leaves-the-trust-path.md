---
id: TASK-166
title: >-
  ti-pki: TSL trust from the detached signature (.sig) and the signer's OCSP
  (.ocsp); XMLDSig leaves the trust path
status: To Do
assignee: []
created_date: '2026-11-01T16:10:00Z'
labels:
  - ti-pki
  - rust
  - spec
  - security
  - deps
dependencies: []
priority: high
ordinal: 176000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
gemSpec_TSL V1.25.0 6.3.1.3 (A_21175 to A_21182): the TSL service publishes, per environment on the CRL host over plain HTTP, the TSL (.xml), a detached signature of the whole file by the same TSL signer (.sig: ASN.1 SEQUENCE of AlgorithmIdentifier ecdsa-with-SHA256, BIT STRING signature in BSI TR-03111 5.2.2 format, and the signer certificate) and an hourly OCSP response for that signer (.ocsp); .xml and .sig are kept consistent (A_21177). Checked live 2026-11-01: PU http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.{xml,sig,ocsp}, RU http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.{xml,sig,ocsp}, TU http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test.{xml,sig,ocsp}, all 200; signer brainpoolP256r1 issued by GEM.TSL-CA3, which is a compiled-in anchor (anchors.rs). The tsl.ti-dienste.de HTTPS hosts ti-pki uses serve only .xml and .sha2. With the detached signature the TSL trust path needs no XML signature, no canonicalization and no XAdES: ti-xmldsig, the C14N code and the second XML parser (TASK-57) leave the core every stack embeds, and the server helper gets small. Deviation: gemSpec_PKI V2.28.0 8.2.6 / A_30044 tells internet consumers to run TUC_PKI_001, whose step 4 is TUC_PKI_012 XML-Signatur-Pruefung, and names the files a fallback for Konnektors (A_21175); .sig-only verification is cryptographically equivalent (same signer, same anchor, same OCSP) but a deviation to be recorded in the spec and, if the pre-release TI 2.0 internet requirements exclude it, taken to gematik's PKI team as a request for change (maintainer, 2026-11-01). Rules: docs/architecture.md trust from verification only; docs/design/testing.md fuzzing; docs/conventions/dependencies.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the gate of step 1 is settled and recorded (requirements cited, or deviation recorded and the request for change written)
- [ ] #2 the TSL verifies from .sig and .ocsp in PU, RU and TU with the spec/tsl-detached corpus; the same CA list and verdicts as the XMLDSig path on the same TSL, measured before the removal
- [ ] #3 fuzz targets for the .sig parser and the XML reader in place and run by just fuzz
- [ ] #4 ti-xmldsig, the C14N code and the second XML parser removed from the workspace; ti-wasm and the verification stamps regenerated; release notes written
- [ ] #5 just check and just jwz-recheck green; maintainer HITL
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Gate: the maintainer provides the pre-release TI 2.0 internet requirements. If they allow .sig verification, cite them; if they exclude it, record the deviation from TUC_PKI_012 in the spec's Deviations section and write the request for change (its own task) before the removal lands. Quote gemSpec_TSL A_21175 to A_21182 and gemSpec_PKI A_30044 / TUC_PKI_001 either way. 2. Loader: fetch .xml, .sig and .ocsp from the CRL hosts (A_21182 URIs; plain HTTP is acceptable, trust comes from verification) as a consistent set, re-fetch all on a mismatch, keep the .sha2 hash compare before download (A_30044). 3. Verify: parse .sig (three fields, bounded), ecdsa-with-SHA256 over the whole .xml bytes with the embedded signer certificate, the signer verified against the compiled-in TSL signer anchors (TUC_PKI_011), its status from .ocsp through the existing OCSP verifier, then the existing update rules (sequence number, freshness, grace, anchor change) unchanged. 4. Parse the TSL XML for the CA list with one hardened XML reader and no canonicalization. 5. spec/tsl-detached: rule IDs, result codes, fixtures from all three environments captured together with their capture time, negative cases (wrong signer, mismatched pair, stale or revoked .ocsp, truncated .sig), fuzz targets for the .sig parser and the XML reader; ti pki tsl reports which path verified the TSL. 6. Removals, each a criterion: ti-xmldsig, the XMLDSig feature of ti-pki, the C14N code, the second XML parser; ti-wasm, the browser stamp and the jwz verification stamps follow; release notes; the dependency removals recorded.
<!-- SECTION:PLAN:END -->
