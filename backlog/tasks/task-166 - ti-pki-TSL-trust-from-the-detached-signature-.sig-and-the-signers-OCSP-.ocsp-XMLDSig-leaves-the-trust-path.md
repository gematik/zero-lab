---
id: TASK-166
title: >-
  ti-pki: TSL trust from the detached signature (.sig) and the signer's OCSP
  (.ocsp); XMLDSig leaves the trust path
status: In Progress
assignee: []
created_date: '2026-11-01T16:10:00Z'
updated_date: '2026-11-01T17:38:00Z'
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
- [x] #2 the TSL verifies from .sig and .ocsp in PU, RU and TU with the spec/tsl-detached corpus; the same CA list and verdicts as the XMLDSig path on the same TSL, measured before the removal
- [x] #3 fuzz targets for the .sig parser and the XML reader in place and run by just fuzz
- [ ] #4 ti-xmldsig, the C14N code and the second XML parser removed from the workspace; ti-wasm and the verification stamps regenerated; release notes written
- [ ] #5 just check and just jwz-recheck green; maintainer HITL
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
# TSL trust from the detached signature: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ti-pki verifies the TSL by gematik's detached signature file (`.sig`) and the published signer status (`.ocsp`), in every environment, through the loaders, the CLI, ti-report and ti-wasm; XMLDSig stays as the fallback until the gate of step 1 of the task lets it be removed (a separate pull request).

**Architecture:** A second part A for `spec/tsl-xmldsig`: `verify_detached` parses the three-field DER file, verifies the ECDSA signature over the raw TSL bytes with the embedded signer and hands a `SignedTsl` to the existing parts B–G (`verify_signed`, factored out of `parse_verified`). The loaders learn two artefacts, `TslSignature` and `TslSignerStatus`, fetched from the environment's automated download point (the CRL host, A_21182) together with the `.xml` after the `.sha2` compare; verification prefers the detached material when present. The supplied `.ocsp` is checked by the existing OCSP verifier with a two-hour maximum age; stale is ignored with the `no_ocsp_check` warning, invalid fails.

**Tech Stack:** Rust 2024 (workspace toolchain), `der` 0.8, `x509-cert` 0.3, `ecdsa` 0.17 with `bp256`, `quick-xml` (already), `cargo-fuzz` on the pinned nightly, Python 3 standard library for the fixture tool.

**Spec:** this task's description (TASK-166) and doc-2 section 6; the rules are written in Task 1 as `spec/tsl-detached/README.md` and every later task cites them.

## Global Constraints

- No new dependency in any crate (`docs/conventions/dependencies.md`); `der`, `x509-cert`, `ecdsa`, `bp256` are already ti-pki dependencies.
- `unsafe_code = "forbid"` stays; `just check` in `rust/` green after every task (fmt, clippy, tests, `just core-deps`, `just wasm32`, `just unsafe-free`).
- Every new source file starts with the EUPL header its neighbours use; comments explain why, never what; tests are named after the rule they prove (`tsldet_005_…`), gated tests skip loudly.
- Public API changes are 0.x breaking changes recorded under `## Unreleased` of `rust/ReleaseNotes.md` per crate (`#### added`, `#### changed`).
- The `.sig` is the X9.62 DER form gematik publishes; the TR-03111 plain form (64 bytes `r‖s`) that A_21179 cites is rejected (fail closed, recorded as a deviation).
- Limits: `.sig` at most 8192 bytes; strict DER, no trailing bytes; BIT STRING with zero unused bits.
- Fixtures: the nine files captured 2026-11-01 (scratchpad `tsl-detached/`, `captured-at.txt`), TEST-ONLY material for RU/TU, the PU set is public data. Negative fixtures are derived by a committed, dependency-free Python tool run with `python3 -I`.
- The CLI guide `rust/ti-cli/AGENTS.md` changes in the same commit as a command.

## Review Focus

1. A `.sig` with bytes after the outer SEQUENCE, or a BIT STRING with unused bits, must be rejected, not silently trimmed (Task 2 tests `tsldet_001_trailing_bytes_rejected`, `tsldet_003_unused_bits_rejected`).
2. A valid `.sig` of the other environment (PU signer under the RU configuration) must fail on the anchor, not verify (Task 3 `tsldet_030_signer_of_another_environment_rejected`).
3. An `.ocsp` that is fresh but about another certificate, or empty, must fail the list; only "older than the maximum" is ignored (Task 4 `tsldet_020_status_for_another_certificate_is_an_error`, `tsldet_020_empty_status_is_an_error`).
4. The `.xml` from the detached origin must equal the `.sha2` published on the HTTPS host; a mismatch is a retryable load error, never a verified list (Task 5 `tsldet_010_list_not_matching_published_hash_is_retryable`).
5. An old bundle without the detached fields must still load (Task 5 `bundle_without_detached_fields_reads`).

---

### Task 1: The specification and its corpus

**Files:**
- Create: `spec/tsl-detached/README.md`, `spec/tsl-detached/CONFORMANCE.md`
- Create: `spec/tsl-detached/testdata/README.md` (capture time, URLs, hashes), `testdata/manifest.json`
- Create: `spec/tsl-detached/testdata/{prod,ref,test}/ECC-RSA_TSL{,-ref,-test}.{xml,sig,ocsp}` (copied from the scratchpad capture of 2026-11-01)
- Create: `spec/tsl-detached/tool/derive.py` and its outputs under `testdata/derived/`
- Modify: `spec/README.md` (table row), `docs/interop.md` candidates line (already names `spec/tsl-detached`: no change)

**Interfaces:**
- Produces: rule identifiers `TSLDET-nnn`, the result code `detached_signature_error`, the manifest schema (below) that Tasks 2–5 read fixtures from.

- [ ] **Step 1: Write `README.md`** with the sections of `spec/README.md`: Scope (the detached signature replaces part A of `spec/tsl-xmldsig`; parts B–G apply unchanged), References (gemSpec_TSL V1.25.0 6.3.1.3 A_21175–A_21182; gemSpec_PKI V2.28.0 8.2.6 A_30044, TUC_PKI_001, TUC_PKI_011, TUC_PKI_012; BSI TR-03111 5.2; X9.62 / RFC 5480 ECDSA-Sig-Value; RFC 6960), File profile (the DER structure as decoded 2026-11-01: `SEQUENCE { AlgorithmIdentifier { ecdsa-with-SHA256 }, BIT STRING (DER ECDSA-Sig-Value), Certificate }`, 712/763/762 bytes), Rules:

| ID | Rule | Code |
|---|---|---|
| TSLDET-001 | The `.sig` file MUST be at most 8192 bytes and strict DER: exactly one SEQUENCE of three elements, no trailing bytes. | `detached_signature_error` |
| TSLDET-002 | Element 1 MUST be the AlgorithmIdentifier `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) with absent parameters; `rsaPSS` (the TSL(RSA)) and every other algorithm MUST be rejected. | `detached_signature_error` |
| TSLDET-003 | Element 2 MUST be a BIT STRING with zero unused bits whose content is a DER `ECDSA-Sig-Value` (SEQUENCE of two INTEGERs) with `0 < r < n`, `0 < s < n` for brainpoolP256r1. The 64-byte plain form MUST be rejected. | `detached_signature_error` |
| TSLDET-004 | Element 3 MUST be a parsable DER X.509 certificate, the signer, with a brainpoolP256r1 key (TSLSIG-012). | `tsl_cert_extraction_error` |
| TSLDET-005 | The signature MUST verify with the signer's key over the complete bytes of the `.xml` file as received, after transport decoding and before any parsing; no canonicalization, no transformation, SHA-256. | `detached_signature_error` |
| TSLDET-006 | The list MUST be read from exactly the verified bytes (as TSLSIG-023); an enveloped `ds:Signature` element inside them is content and MUST be ignored, not verified. | `tsl_not_wellformed` for unparsable content |
| TSLDET-010 | `.xml`, `.sig` and `.ocsp` MUST be fetched from the configured automated download point of the environment (A_21182), the same origin, as one set; before that the `.sha2` of the HTTPS download point (A_30044 (2), TSLSIG-050) MUST be compared and the fetched `.xml` MUST match it. A set whose signature does not verify is discarded whole and the next attempt fetches all three again (A_21177). | `tsl_download_error`, `detached_signature_error` |
| TSLDET-011 | Plain `http://` is acceptable for the download point (A_21175 mandates it): trust comes from the signature and the hash, never from the transport. | |
| TSLDET-020 | A supplied `.ocsp` MUST be verified like a queried response (TSLSIG-040, 041: authorized responder, certHash, status), with `producedAt` at most 2 hours before the validation time (A_21181 renews hourly) and not after it beyond the clock tolerance. Revoked, unknown, unauthorized, mismatching or unparsable → the list MUST NOT be used. | codes of TSLSIG-040–042 |
| TSLDET-021 | A supplied `.ocsp` older than the maximum MUST NOT be used; the status is then "not queried" (TSLSIG-043) with the age in the detail, and a network query (TSLSIG-040) MAY replace it. | `no_ocsp_check` (warning) |
| TSLDET-030 | Parts B–G of `spec/tsl-xmldsig` apply unchanged to the signer from element 3 and the list from TSLDET-006. | as there |
| TSLDET-031 | The result MUST name the signature kind, `detached` or `enveloped`. | |

  Result codes: `detached_signature_error` (own code, no Tab_PKI_274 number; the enveloped path's `xml_signature_error` 1013 is its counterpart), the others as `spec/tsl-xmldsig`. Algorithm (pseudo-code as the existing spec writes it). Requirement mapping (A_21175: 011; A_21176, A_21182: 010; A_21177: 010; A_21179: 001–005; A_21181: 020, 021; A_30044: 010, 020; TUC_PKI_011: 030; TUC_PKI_012: replaced). Deviations: TUC_PKI_012 replaced for internet consumers (gate of TASK-166, doc-3); A_21179 cites TR-03111 5.2.2 (plain) while the published files carry X9.62 DER, DER is accepted and plain rejected (doc-3 question 4). Security considerations (exact bytes signed; no canonicalization class; replay unchanged through D; stale status is not evidence; HTTP transport). Licence as the sibling spec.

- [ ] **Step 2: Write `CONFORMANCE.md`**: corpus layout (`testdata/<env>/`, `testdata/derived/`), the manifest schema:

```json
{ "path": "ref/ECC-RSA_TSL-ref.xml", "signature": "ref/ECC-RSA_TSL-ref.sig",
  "signer_status": "ref/ECC-RSA_TSL-ref.ocsp", "producer": "gematik-ru",
  "rules": ["TSLDET-005", "TSLDET-020"], "time": "<captured-at>", "env": "nonprod",
  "expect": { "result": "valid", "code": null, "rule": null, "warnings": [],
              "signature": "detached", "signer_serial": "06", "sequence_number": 0 } }
```

  (`sequence_number` filled from the file; `signer_status` optional; `expect.rule` the TSLDET rule of an invalid fixture.) The command-line contract as the sibling spec, and the conformance definition (every manifest entry matched; every rule covered by an entry or a named test; the published sets of PU, RU, TU verify).

- [ ] **Step 3: Copy the capture** from `/private/tmp/claude-501/-Users-serg-Development-gematik-zero-lab/8e5cc058-ff77-4809-b88f-a7b1faf6ebb1/scratchpad/tsl-detached/{prod,ref,test}.{xml,sig,ocsp}` to `testdata/<env>/<published name>`; write `testdata/README.md` with the capture time from `captured-at.txt`, the nine URLs, SHA-256 of each file, the signer subjects, and that the PU set is public data and RU/TU are TEST-ONLY.

- [ ] **Step 4: Write `tool/derive.py`** (standard library only; `python3 -I tool/derive.py testdata`) producing into `testdata/derived/`: `prod-sig-on-ref-xml.sig` (= prod `.sig`, paired with `ref/…xml`), `ref-truncated.sig` (first 700 bytes), `ref-trailing-byte.sig` (one `0x00` appended), `ref-flipped-signature-byte.sig` (last byte of the BIT STRING content XOR 0x01), `ref-wrong-algorithm.sig` (OID patched to 1.2.840.10045.4.3.3), `ref-plain-signature.sig` (ECDSA-Sig-Value replaced by `r‖s`, BIT STRING length adjusted, outer lengths re-encoded), `ref-unused-bits.sig` (BIT STRING unused-bits byte set to 1), `ref-tampered.xml` (byte at offset 1000 XOR 0x01), and `stale.ocsp` copied from `rust/ti-pki/tests/fixtures/ocsp-tsl-signing-unit-12-test-only.der` (produced 2026-10-03). It prints the manifest entries for them; commit the outputs.

- [ ] **Step 5: Write `manifest.json`**: three valid entries (rules 001–006, 020, 030, 031; `warnings: []`), and the derived ones: truncated → 001, trailing → 001, wrong algorithm → 002, plain → 003, unused bits → 003, prod-sig-on-ref → 005, tampered xml → 005, stale ocsp → valid with `warnings: ["no_ocsp_check"]` (021). Run `python3 -I -c "import json;json.load(open('spec/tsl-detached/testdata/manifest.json'))"`: no error.

- [ ] **Step 6: Add the row to `spec/README.md`**: `| [tsl-detached](tsl-detached/README.md) | TSL verification by the detached signature and the published signer status | rust/ti-pki |`.

- [ ] **Step 7: Commit** `git add spec && git commit -m "spec/tsl-detached: the TSL's detached signature and signer status as a trust path"`.

### Task 2: `verify_detached` in ti-pki

**Files:**
- Modify: `rust/ti-pki/src/tsl_signature.rs` (`TslCode`, after `verify` at l.300; tests module)
- Test: same file, `mod tests`

**Interfaces:**
- Consumes: `Certificate::from_der`, `Certificate::public_key_alg_id/public_key`, `algorithms::find`, `BRAINPOOL_P256R1`, `ecdsa::Signature::<BrainpoolP256r1>::from_der`, fixtures of Task 1.
- Produces:
  - `TslCode::DetachedSignatureError` (`as_str` → `"detached_signature_error"`, `number` → `None`, in `ALL`);
  - `pub const MAX_DETACHED_SIGNATURE_LEN: usize = 8192;`
  - `#[non_exhaustive] pub struct DetachedSignature { pub signer: Certificate, pub signature: Vec<u8> /* DER ECDSA-Sig-Value, re-encoded */ }`
  - `pub fn parse_detached_signature(sig: &[u8]) -> Result<DetachedSignature, TslError>` (TSLDET-001–004; fuzz entry point);
  - `#[cfg(feature = "brainpool")] pub fn verify_detached(xml: &[u8], sig: &[u8], algorithms: &AlgorithmSet) -> Result<SignedTsl, TslError>` (TSLDET-005) returning `SignedTsl { signer, content: xml.to_vec(), signing_time: None }` — `signing_time` becomes `Option<String>` in Task 3; in this task keep `String::new()` and note it.

- [ ] **Step 1: Write the failing tests** in `mod tests` (helper `detached(env) -> (Vec<u8> xml, Vec<u8> sig, Vec<u8> ocsp)` reading `spec/tsl-detached/testdata/<env>/…` through `concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/tsl-detached/testdata/")`, and `derived(name)`):

```rust
#[test] fn tsldet_005_published_sets_verify() { for env in ["prod","ref","test"] { let (xml,sig,_)=detached(env); let signed = verify_detached(&xml,&sig,crate::algorithms::DEFAULT).unwrap(); assert_eq!(signed.content, xml); assert_eq!(signed.signer.serial_hex(), "06"); } }
#[test] fn tsldet_001_truncated_rejected()        { assert_code(verify_detached(&xml("ref"), &derived("ref-truncated.sig"), DEFAULT), TslCode::DetachedSignatureError, "TSLDET-001"); }
#[test] fn tsldet_001_trailing_bytes_rejected()   { … "ref-trailing-byte.sig" … "TSLDET-001" }
#[test] fn tsldet_001_oversized_rejected()        { let mut big = sig("ref"); big.resize(MAX_DETACHED_SIGNATURE_LEN + 1, 0); … "TSLDET-001" }
#[test] fn tsldet_002_wrong_algorithm_rejected()  { … "ref-wrong-algorithm.sig" … "TSLDET-002" }
#[test] fn tsldet_003_plain_signature_rejected()  { … "ref-plain-signature.sig" … "TSLDET-003" }
#[test] fn tsldet_003_unused_bits_rejected()      { … "ref-unused-bits.sig" … "TSLDET-003" }
#[test] fn tsldet_004_unparsable_signer_is_cert_extraction_error() { /* patch the certificate's first byte to 0x31 */ … TslCode::TslCertExtractionError, "TSLDET-004" }
#[test] fn tsldet_005_tampered_list_rejected()    { verify_detached(&derived("ref-tampered.xml"), &sig("ref"), …) → DetachedSignatureError, "TSLDET-005" }
#[test] fn tsldet_005_signature_of_another_list_rejected() { verify_detached(&xml("ref"), &sig("prod"), …) → DetachedSignatureError, "TSLDET-005" }
```

  `assert_code(result, code, rule)` asserts `Err` with `e.code == code && e.rule == rule`. Use the existing `serial` accessor name of `Certificate` (check `cert.rs`; the plan assumes a hex serial accessor exists or compare `signer.serial()` with the known serial 6).

- [ ] **Step 2: Run them** `cargo test -p ti-pki tsldet_ -- --nocapture`: compile errors (functions missing).

- [ ] **Step 3: Implement** in `tsl_signature.rs`: the enum variant with its doc comment and `ALL`/`as_str`/`number` arms; `parse_detached_signature` with a `der::SliceReader` over the input (length check first), `reader.sequence(|r| { AlgorithmIdentifierOwned::decode(r); BitStringRef::decode(r); r.tlv_bytes() for the certificate })`, then `reader.finish(())` to refuse trailing bytes; OID compared with `const_oid::db::rfc5912::ECDSA_WITH_SHA_256` and `parameters.is_none()`; `BitStringRef::as_bytes()` (None when unused bits ≠ 0) → `ecdsa::Signature::<bp256::BrainpoolP256r1>::from_der(bytes)?.to_der()` (this enforces strict DER and the range of r, s); `Certificate::from_der(cert_der)` → `TslCertExtractionError`; key must be `BRAINPOOL_P256R1`. `verify_detached`: `find(algorithms, BRAINPOOL_P256R1, alg_id::ECDSA_SHA256)` then `verify_signature(signer.public_key(), xml, &signature)`. Errors use `TslError::new(TslCode::DetachedSignatureError, "TSLDET-00n", detail)`.

- [ ] **Step 4: Run** `cargo test -p ti-pki tsldet_`: PASS. `cargo clippy -p ti-pki --all-targets`: clean.

- [ ] **Step 5: Commit** `git commit -am "ti-pki: verify the TSL by its detached signature file (TSLDET-001 to 005)"`.

### Task 3: One verification for both signatures; the detached entry point

**Files:**
- Modify: `rust/ti-pki/src/tsl_signature.rs` (`SignedTsl`, `VerifiedTsl`, `parse_verified` l.536, `embedded_config_for` l.636, `parse_verified_auto`)
- Modify: `rust/ti-pki/src/lib.rs` (re-exports), `rust/ti-report/src/tsl_view.rs:76-95,281,383` and `rust/ti-cli/src/commands/tsl.rs` (only where `signing_time: String` no longer compiles; the real changes come in Tasks 6 and 7)
- Test: `tsl_signature.rs` tests

**Interfaces:**
- Produces:
  - `pub enum SignatureKind { Enveloped, Detached }` with `pub const fn as_str(self) -> &'static str` (`"enveloped"`, `"detached"`), re-exported from the crate root;
  - `SignedTsl.signing_time: Option<String>`; `VerifiedTsl.signing_time: Option<String>`; `VerifiedTsl.signature: SignatureKind`;
  - `pub struct DetachedTsl<'a> { pub signature: &'a [u8], pub signer_status: Option<&'a [u8]> }` (re-exported; the input bundle ti-report and the loaders pass around);
  - `impl Tsl { pub fn parse_verified_detached(xml: &[u8], sig: &[u8], config: &TrustConfig, now: Timestamp) -> Result<VerifiedTsl, TslError> }`;
  - `pub fn embedded_config_for_detached(sig: &[u8]) -> Result<TrustConfig, TslError>`;
  - private `fn verify_signed(signed: SignedTsl, kind: SignatureKind, config: &TrustConfig, now: Timestamp) -> Result<VerifiedTsl, TslError>` holding the body of today's `parse_verified` from `issuing_anchor` on, and `fn config_for_signer(signer: &Certificate) -> Result<TrustConfig, TslError>` shared by both `embedded_config_for*`.

- [ ] **Step 1: Write the failing tests**:

```rust
#[test] fn tsldet_030_detached_list_passes_parts_b_to_g() { for (env, preset) in [("prod", Env::Prod), ("ref", Env::Ref), ("test", Env::Test)] { let (xml, sig, _) = detached(env); let at = captured_at(); let v = Tsl::parse_verified_detached(&xml, &sig, &TrustConfig::preset(preset), at).unwrap(); let x = Tsl::parse_verified(&xml, &TrustConfig::preset(preset), at).unwrap(); assert_eq!(v.tsl.id, x.tsl.id); assert_eq!(v.tsl.sequence_number, x.tsl.sequence_number); assert_eq!(v.tsl.services.len(), x.tsl.services.len()); assert_eq!(v.signer.serial(), x.signer.serial()); assert_eq!(v.signature, SignatureKind::Detached); assert_eq!(x.signature, SignatureKind::Enveloped); assert_eq!(v.signing_time, None); assert!(x.signing_time.is_some()); assert_eq!(v.warnings.iter().map(|w| w.code).collect::<Vec<_>>(), x.warnings.iter().map(|w| w.code).collect::<Vec<_>>()); } }
#[test] fn tsldet_030_signer_of_another_environment_rejected() { let (xml, sig, _) = detached("prod"); assert_code(Tsl::parse_verified_detached(&xml, &sig, &TrustConfig::preset(Env::Ref), captured_at()), TslCode::CertificateNotValidMath, "TSLSIG-031"); }
#[test] fn tsldet_031_embedded_config_follows_the_detached_signer() { assert_eq!(embedded_config_for_detached(&sig("prod")).unwrap().tsl_url, tsl::URL_PROD); assert_eq!(embedded_config_for_detached(&sig("ref")).unwrap().tsl_url, tsl::URL_REF); }
```

  `captured_at()` parses `testdata/README.md`'s time or a constant copied from it (a `const CAPTURED_AT: &str` in the test module is fine). `Env::Test` and `Env::Ref` presets are behind `dangerous-nonprod`; tests already run with it (see existing tests).

- [ ] **Step 2: Run** `cargo test -p ti-pki tsldet_03`: compile errors.

- [ ] **Step 3: Implement** the refactor: move the body of `parse_verified` after `let signed = verify(xml, &config.algorithms)?;` into `verify_signed`, which also sets `signature: kind`; `parse_verified` = `verify_signed(verify(xml, algs)?, SignatureKind::Enveloped, config, now)`; `parse_verified_detached` = `verify_signed(verify_detached(xml, sig, algs)?, SignatureKind::Detached, …)`. `SignedTsl.signing_time: Option<String>` (`Some(xml_checked.signing_time)` in `verify`, `None` in `verify_detached`). Extract `config_for_signer`. Fix every compile error in ti-pki, ti-report and ti-cli minimally (`signing_time` Option; ti-report `SignatureView.signing_time: Option<String>`).

- [ ] **Step 4: Run** `cargo test -p ti-pki` and `cargo build --workspace`: PASS.

- [ ] **Step 5: Commit** `git commit -am "ti-pki: parse_verified_detached shares parts B to G with the enveloped path"`.

### Task 4: The supplied signer status

**Files:**
- Modify: `rust/ti-pki/src/tsl_signature.rs` (`impl VerifiedTsl`, near `check_signer_status` l.419; `status_error` l.492)
- Test: same file

**Interfaces:**
- Consumes: `ocsp::verify_response(der, cert, issuer, &ResponseCheck)`, `ResponseCheck::new(now, algorithms)` with `max_response_age` overridden, `RevocationResult`, `status_error`.
- Produces:
  - `pub const MAX_SUPPLIED_SIGNER_STATUS_AGE: Duration = Duration::from_hours(2);`
  - `impl VerifiedTsl { pub fn check_signer_status_supplied(&mut self, response: &[u8], now: Timestamp, algorithms: &AlgorithmSet) -> Result<bool, TslError> }` — `Ok(true)`: used, `signer_status` set, `no_ocsp_check` removed; `Ok(false)`: older than the maximum, the `no_ocsp_check` warning's detail now says `"the supplied status is <age> old, older than <max>"`; `Err`: TSLSIG-040–042 codes.
  - private `fn adopt_signer_status(&mut self, result: RevocationResult, how: &str) -> Result<(), TslError>` (the match of `check_signer_status`, with `how` = the responder URL or `"supplied"` in details), used by both check methods.

- [ ] **Step 1: Write the failing tests**:

```rust
#[test] fn tsldet_020_supplied_status_good_at_capture_time() { for env … { let mut v = parse_detached(env); assert_eq!(v.check_signer_status_supplied(&ocsp(env), captured_at(), DEFAULT).unwrap(), true); assert!(v.signer_status.as_ref().unwrap().status == RevocationStatus::Good); assert!(!v.warnings.iter().any(|w| w.code == TslCode::NoOcspCheck)); } }
#[test] fn tsldet_021_supplied_status_older_than_the_maximum_is_not_used() { let mut v = parse_detached("ref"); assert_eq!(v.check_signer_status_supplied(&derived("stale.ocsp"), captured_at(), DEFAULT).unwrap(), false); let w = v.warnings.iter().find(|w| w.code == TslCode::NoOcspCheck).unwrap(); assert!(w.detail.contains("older than")); assert!(v.signer_status.is_none()); }
#[test] fn tsldet_020_status_for_another_certificate_is_an_error() { let mut v = parse_detached("ref"); let e = v.check_signer_status_supplied(&ocsp("prod"), captured_at(), DEFAULT).unwrap_err(); assert!(matches!(e.code, TslCode::CerthashMismatch | TslCode::OcspCheckRevocationError | TslCode::OcspSignatureError)); }
#[test] fn tsldet_020_empty_status_is_an_error() { … check_signer_status_supplied(&[], …) → Err with rule "TSLSIG-042" }
#[test] fn tsldet_020_status_from_the_future_is_an_error() { … check_signer_status_supplied(&ocsp("ref"), captured_at() - Duration::from_hours(3), …) → Err }
```

- [ ] **Step 2: Run** `cargo test -p ti-pki tsldet_02`: compile errors.

- [ ] **Step 3: Implement**: build `ResponseCheck { max_response_age: MAX_SUPPLIED_SIGNER_STATUS_AGE, ..ResponseCheck::new(now, algorithms) }`; on `Ok(result)` → `adopt_signer_status(result, "supplied")` then `Ok(true)`. On `Err(e)`: if `e` is the time-window failure (inspect `ValidationError.defect`/message as `ocsp::outside_window` produces it; if the defect does not tell "too old" from "in the future", re-run `verify_response` with `max_response_age: Duration::from_days(400)` and treat success as "too old"), set the warning detail and return `Ok(false)`; every other error → `Err(status_error(&e))`. Refactor `check_signer_status` to use `adopt_signer_status`.

- [ ] **Step 4: Run** `cargo test -p ti-pki tsl`: PASS, including the existing `tslsig_040_*` tests.

- [ ] **Step 5: Commit** `git commit -am "ti-pki: the published .ocsp as the TSL signer's status (TSLDET-020, 021)"`.

### Task 5: The loaders fetch the set; verification prefers it

**Files:**
- Modify: `rust/ti-pki/src/load/artifact.rs` (`Artifact`, `TrustMaterial`), `loader.rs` (`load_all`), `http.rs` (`HttpLoader`), `file.rs` (`FileTransport`), `static_.rs` (`Wire`), `verify.rs` (`verify_bytes`, `verify_tsl`), `reload.rs` (`tick` l.476, `same_etags` l.609, `Current.etags`), `mod.rs` (docs and re-exports)
- Modify: `rust/ti-pki/src/config.rs` (`TrustConfig`, presets, `validate`), `rust/ti-pki/src/tsl.rs` (URL constants)
- Test: the `tests` modules of the files above (MockTransport, FixedClock exist)

**Interfaces:**
- Produces:
  - `Artifact::TslSignature` (`"tsl-sig"`), `Artifact::TslSignerStatus` (`"tsl-ocsp"`);
  - `pub struct Detached { pub signature: Vec<u8>, pub signature_meta: Meta, pub signer_status: Option<(Vec<u8>, Meta)> }` in `artifact.rs`; `TrustMaterial.detached: Option<Detached>`; `TrustMaterial::with_detached(self, Detached) -> Self` (recomputes `fetched_at` as the minimum); `TrustMaterial::body/meta` return `Option<&[u8]>` / `Option<&Meta>` for every artefact (breaking; callers updated);
  - `TrustConfig.tsl_detached_url: Option<Cow<'static, str>>` with `tsl::URL_DETACHED_PROD = "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.xml"`, `URL_DETACHED_REF = "http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.xml"`, `URL_DETACHED_TEST = "http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test.xml"` set by the presets; `validate()` accepts `http://` or `https://` here (A_21175) and requires the `.xml` suffix;
  - `HttpLoader`: `.sig`/`.ocsp` URLs derived by replacing the `.xml` suffix; with a detached URL the TSL body is fetched from it after the `.sha2` of `tsl_url` was read, and must match the published hash (existing check); without one, `fetch(TslSignature|TslSignerStatus)` → `LoadError::Unavailable`;
  - `Loader::load_all`: loads the two detached artefacts after roots and TSL; any error on `TslSignature` → `detached: None` (documented as the transition behaviour: the enveloped path still verifies; it becomes an error when XMLDSig is removed); any error on `TslSignerStatus` → `signer_status: None`;
  - `FileTransport::with_detached(self, signature: impl Into<PathBuf>, signer_status: Option<PathBuf>) -> Self`;
  - bundle `Wire` fields `tsl_sig`, `tsl_sig_meta`, `tsl_ocsp`, `tsl_ocsp_meta`, all `Option` with `#[serde(default, skip_serializing_if = "Option::is_none")]`, `FORMAT_VERSION` unchanged;
  - `verify_bytes(config, roots_json, tsl_xml, detached: Option<&Detached>, now, stored)`: detached → `Tsl::parse_verified_detached` then, with a status, `check_signer_status_supplied(status, now, &config.algorithms)?` (an `Err` fails verification); otherwise the enveloped path;
  - `Reloader::tick`: the network checker runs only when `tsl.signer_status.is_none()`; `Current.etags` becomes `[Option<String>; 4]` and `same_etags` compares all four (a missing detached meta compares as `None`).

- [ ] **Step 1: Write the failing tests** (in the respective modules):

```rust
// http.rs
#[test] fn tsldet_010_http_loader_fetches_the_set_from_the_detached_origin() { /* MockTransport answering .sha2 (hash of ref xml), the ref xml at the detached URL, .sig, .ocsp; HttpLoader::new(&preset(Env::Ref), transport, FixedClock); load_all(); assert detached.is_some(), signer_status.is_some(); assert the request URLs in order: tsl_url+".sha2", roots_url, URL_DETACHED_REF, URL_DETACHED_REF with .sig, with .ocsp */ }
#[test] fn tsldet_010_list_not_matching_published_hash_is_retryable() { /* .sha2 says another hash → load_all Err(LoadError::Transport(e)) with e.retryable */ }
#[test] fn load_all_without_detached_url_has_no_detached_material() { /* config.tsl_detached_url = None → detached None, no .sig request made */ }
#[test] fn a_failing_sig_download_leaves_the_enveloped_path() { /* .sig answers 500 → Ok(material) with detached None */ }
// file.rs
#[test] fn file_transport_reads_detached_files() { … with_detached(sig_path, Some(ocsp_path)) → load_all → detached Some … }
// static_.rs
#[test] fn bundle_round_trips_detached_material() { … }
#[test] fn bundle_without_detached_fields_reads() { /* a JSON written by today's Wire without the new fields → Ok, detached None */ }
// verify.rs
#[test] fn tsldet_031_verify_material_prefers_detached() { /* material with detached → verified.tsl.signature == Detached and signer_status Some */ }
// reload.rs
#[test] fn tsldet_021_reloader_skips_the_network_checker_when_the_status_was_supplied() { /* with_signer_status(checker that panics or records calls) and a material with a fresh .ocsp: tick → swapped, checker not called */ }
// config.rs
#[test] fn presets_carry_the_detached_download_points() { … }
#[test] fn validate_accepts_http_for_the_detached_download_point() { … and rejects a URL without .xml }
```

- [ ] **Step 2: Run** `cargo test -p ti-pki --features os,load`: compile errors.

- [ ] **Step 3: Implement** in the order artifact → loader → http → file → static_ → config/tsl → verify → reload, fixing callers of `body()`/`meta()` (`grep -rn "\.body(Artifact\|\.meta(Artifact" rust/`). Keep the module docs of `load/mod.rs` and `http.rs` in step (the pipeline diagram gains the two artefacts; the hash rule paragraph says the body comes from the detached origin when configured).

- [ ] **Step 4: Run** `cargo test -p ti-pki --all-features` and `cargo test -p ti-pki --no-default-features --features load` (wasm-compatible path), `just core-deps`, `just wasm32`: PASS.

- [ ] **Step 5: Commit** `git commit -am "ti-pki: load the TSL with its detached signature and signer status (TSLDET-010, 020, 021)"`.

### Task 6: The CLI

**Files:**
- Modify: `rust/ti-cli/src/cli.rs` (`TslVerifyArgs` l.529), `rust/ti-cli/src/commands/tsl.rs` (`verify` l.282, `VerifyReport` l.228, `Report` of `show` l.57, `verify_report`, `verify_document`), `rust/ti-cli/src/trust.rs` (`Session::tsl` l.456: load `TslSignature`/`TslSignerStatus` beside the TSL and use `parse_verified_detached` when present), `rust/ti-cli/AGENTS.md` (recipes l.106), `rust/ti-cli/tests/cli.rs`, the schema fixtures under `rust/ti-cli/tests` if `cargo test -p ti-cli --test schema` reports a difference (regenerate with its documented variable, never by hand)

**Interfaces:**
- Produces: `ti pki tsl verify FILE --signature FILE.sig [--signer-status FILE.ocsp]`; `--signer-status` requires `--signature` (clap `requires`), and means the status is not queried over the network; JSON: `signature: "detached" | "enveloped"` in `VerifyReport` and in `show`'s `Report`, `signing_time` null for detached, `signer_status.responder_url` = `"supplied"` when it came from a file. `--env auto` with `--signature` uses `embedded_config_for_detached`.

- [ ] **Step 1: Write the failing test** in `rust/ti-cli/tests/cli.rs` (pattern of the existing `pki tsl verify` tests): `tsl_verify_detached_reports_the_kind_and_the_supplied_status`: run `pki tsl verify <ref xml> --signature <ref sig> --signer-status <ref ocsp> --at <captured-at> --format json`; expect exit 0, `result == "valid"`, `signature == "detached"`, `signer_status.status == "good"`, `signer_status.responder_url == "supplied"`, `warnings == []`; and `tsl_verify_detached_rejects_a_tampered_list`: `derived/ref-tampered.xml` with the ref `.sig` → exit 1, `code == "detached_signature_error"`, `rule == "TSLDET-005"`.

- [ ] **Step 2: Run** `cargo test -p ti-cli --test cli tsl_verify_detached`: FAIL (unknown argument).

- [ ] **Step 3: Implement**: the two args; in `verify`: read the files, branch on `args.signature`; the status branch: `--signer-status` → `check_signer_status_supplied(...)` (an `Ok(false)` leaves the warning; the report shows no `signer_status`), else the existing network checker unless `--offline`/`--at`; `verify_report` fills `signature` from `verified.signature.as_str()`; text renderer prints `signature: detached` and the supplied status line. `Session::tsl`: load the two artefacts through the session's loader (`Artifact::TslSignature`, `TslSignerStatus`; `Unavailable`/errors → none), verify detached when present, so `show`, `bundle` and `export` use the configured download point automatically. AGENTS.md: add `{bin} --format json pki tsl verify tsl.xml --signature tsl.sig --signer-status tsl.ocsp   # the published detached signature, no network` under the `pki tsl verify` recipe, and one sentence in the pki paragraph that `tsl show` and `tsl export` fetch the list with its detached signature from the environment's automated download point.

- [ ] **Step 4: Run** `cargo test -p ti-cli`: PASS (regenerate the schema fixtures if the schema test asks; commit them in the same commit).

- [ ] **Step 5: Commit** `git commit -am "ti: pki tsl verify --signature and --signer-status; the loaders use the detached signature"`.

### Task 7: ti-report and ti-wasm

**Files:**
- Modify: `rust/ti-report/src/tsl_view.rs` (`tsl_view` l.259, `SignatureView` l.76), `rust/ti-wasm/src/api.rs` (`verify_tsl` l.82), `rust/ti-wasm/src/lib.rs` (l.65), `rust/ti-wasm/tests/native.rs`, `rust/ti-wasm/README.md` if it lists exports
- Test: `rust/ti-report` tests, `rust/ti-wasm/tests/native.rs`

**Interfaces:**
- Produces: `pub fn tsl_view(xml: &[u8], detached: Option<DetachedTsl<'_>>, env: Env, config: &TrustConfig, supplied_roots: Option<&[u8]>, now: Timestamp) -> TslView`; `SignatureView { kind: &'static str, signer, tsl_signer_ca, signing_time: Option<String>, warnings }`; ti-wasm export `verify_tsl_detached(xml: &[u8], signature: &[u8], signer_status: Option<Vec<u8>>, env: &str, now: &str, roots_json: Option<Vec<u8>>, grace_seconds: u32) -> Result<String, JsError>`; `verify_tsl` unchanged in signature, passes `None`.

- [ ] **Step 1: Write the failing tests**: ti-report `tsldet_031_view_names_the_detached_signature` (the ref set at capture time → `result == "valid"`, `signature.kind == "detached"`, `signing_time == None`, `warnings` empty because the status was supplied); ti-wasm `tests/native.rs` `verify_tsl_detached_returns_the_view` (JSON contains `"kind":"detached"`).

- [ ] **Step 2: Run** them: compile errors.

- [ ] **Step 3: Implement**: `tsl_view` branches to `parse_verified_detached` and then `check_signer_status_supplied` when `detached.signer_status` is `Some` (an `Err` becomes `view.error`); `SignatureView.kind = verified.signature.as_str()`. ti-wasm: the new export with the same argument conventions as `verify_tsl` (`clippy::needless_pass_by_value` allowance), `api::verify_tsl_detached` building `DetachedTsl`.

- [ ] **Step 4: Run** `cargo test -p ti-report -p ti-wasm` and `just wasm32`: PASS.

- [ ] **Step 5: Commit** `git commit -am "ti-report, ti-wasm: the TSL view from the detached signature"`.

### Task 8: Fuzz targets

**Files:**
- Create: `rust/ti-pki/fuzz/Cargo.toml` (from `rust/ti-store/fuzz/Cargo.toml`: name `ti-pki-fuzz`, dependency `ti-pki = { path = "..", default-features = true }`), `fuzz_targets/detached_signature.rs`, `fuzz_targets/tsl_xml.rs`, `fuzz_targets/ocsp_response.rs`, `seeds/<target>/` (the three `.sig`, the three `.xml`, the three `.ocsp` plus `stale.ocsp`), `.gitignore` for `corpus/`, `artifacts/`, `target/`
- Modify: `rust/Justfile` (recipe `fuzz-ti-pki seconds="30"` after `fuzz-ti-store`, same shape; the `clean` globs already cover `*/fuzz/target`), `rust/docs/development.md` "Gated tests"/fuzz mention if it lists the recipes, `rust/docs/design.md` §7 target list

**Interfaces:**
- Consumes: `ti_pki::tsl_signature::parse_detached_signature`, `ti_pki::tsl::Tsl::parse`, `ti_pki::ocsp::{verify_response, ResponseCheck}` with the ref signer and GEM.TSL-CA28 TEST-ONLY from the crate's fixtures (`include_bytes!`).

- [ ] **Step 1: Write the three targets** (`fuzz_target!(|data: &[u8]| { let _ = parse_detached_signature(data); })`, etc.; the OCSP target builds the certificates once in a `std::sync::LazyLock`).
- [ ] **Step 2: Build** `cd rust/ti-pki/fuzz && cargo +$JWZ_NIGHTLY fuzz build`: compiles.
- [ ] **Step 3: Run** `just fuzz-ti-pki 20`: three targets, no crash, stats printed.
- [ ] **Step 4: Commit** `git commit -am "ti-pki: fuzz targets for the detached signature, the TSL XML and OCSP responses"`.

### Task 9: Release notes, documents, the full check

**Files:**
- Modify: `rust/ReleaseNotes.md` (`## Unreleased`: `### ti-pki` added/changed; `### ti-cli` added; `### ti-report` changed; `### ti-wasm` added), `rust/ti-pki/README.md` (the TSL paragraph: the detached signature is the preferred trust path, the enveloped one the fallback until TASK-166's gate), `rust/docs/development.md` "The TSL" section (the three files, the download points, the supplied status rule), `rust/docs/design.md` §7 fuzz targets, `rust/ti-pki/src/lib.rs` crate docs if they describe the TSL path

- [ ] **Step 1: Write the release notes** naming the APIs (`verify_detached`, `parse_verified_detached`, `check_signer_status_supplied`, `DetachedTsl`, `SignatureKind`, `Artifact::TslSignature`, `TrustConfig::tsl_detached_url`, the `body()/meta()` change, `signing_time` now optional) with `(TASK-166, gemSpec_TSL A_21175 ff.)`.
- [ ] **Step 2: Update the documents** listed above.
- [ ] **Step 3: Run** `cd rust && just check`: green. If `just check` reports stale stamps, run `just jwz-recheck` and commit the regenerated files.
- [ ] **Step 4: Commit** `git commit -am "ti-pki: release notes and guides for the detached TSL signature"`.
- [ ] **Step 5: Task bookkeeping**: tick TASK-166 criteria 2, 3 (fuzz) as met; criteria 1 (the gate) and 4 (removals) stay open for the follow-up; notes record what was measured (`tsldet_030` equality of both paths) and the maintainer's HITL to run (`ti pki tsl show --env ref` against the live download points, `ti pki tsl verify` with the captured set).

## After this plan (not in it)

The removal of XMLDSig (criterion 4) waits for the gate (criterion 1): a second pull request removes `ti-xmldsig`, the enveloped path, the second XML parser and the `.sig`-missing fallback of Task 5, turns `spec/tsl-xmldsig` part A into history, and regenerates `ti-wasm` and the stamps.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01, branch feat/tsl-detached (9 commits after the plan): spec/tsl-detached with the captured sets of PU, RU, TU and derived negatives; verify_detached, parse_verified_detached, check_signer_status_supplied, the loaders (tsl_detached_url, Artifact::TslSignature/TslSignerStatus, bundle fields, file transport), ti pki tsl verify --signature/--signer-status, ti-report and ti-wasm (verify_tsl_detached), the ti-pki fuzz crate (just fuzz-ti-pki). Measured: tsldet_030 shows identical id, sequence, services, signer, anchor and warnings for the detached and the enveloped path on all three sets. Finding on the way: the ocsp_response fuzz target found a panic in parse_generalized_time (multibyte character across byte 14) within seconds, fixed with a regression test and recorded under ti-pki security. just check: 637/638 (a_closed_pipe_is_not_an_error, TASK-154, fails on main too); just deny fails on main too (TASK-155). Open here: criterion 1 (the gate: the maintainer's check of the pre-release TI 2.0 requirements) and 4 (the XMLDSig removal, a second pull request behind the gate). HITL to run: ti pki tsl show --env ref against the live download points; ti pki tsl verify with the captured set and --signature/--signer-status.
<!-- SECTION:NOTES:END -->
