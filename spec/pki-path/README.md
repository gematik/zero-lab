# Certificate chains from a trust bundle

Language-neutral rules for building and checking a chain without a network, from the bundle file
`ti` writes. `rust/ti-pki` and `go/tipki` implement them, and [`testdata`](testdata) holds the two
together. It covers the path alone: the roots walk, the TSL and OCSP are later stages (TASK-176). A
path that passes is not yet a certificate to trust.

Each rule has one identifier, and tests cite them. MUST and MUST NOT are used as in RFC 2119.

## Chain

- **PATH-001** A chain is walked from the end entity. A certificate's issuer is the root, else the first
  intermediate, whose subject name is its issuer name and whose subject key identifier is its authority
  key identifier where it has one; without one a root is found by common name. A chain ends at a root,
  holds at most 5 certificates and has no cycle. Otherwise it is `chain_incomplete`.
- **PATH-002** The end entity MUST be valid at the reference time, and so must each CA under the shell
  model. Under the Kompromissmodell a CA MUST have been valid when it issued the certificate below it, and
  one expired since is the warning `issued_before_ca_expiry`. The findings are `not_yet_valid` and `expired`.
- **PATH-003** The model follows from the type: C.HP.AUT, C.HP.ENC, C.HCI.AUT, C.HCI.ENC and C.HCI.OSIG are
  under the Kompromissmodell, every other type under the shell model (gemKPT_PKI_TIP 2.4).
- **PATH-004** Every certificate but the root MUST mark critical only the extensions this rule set processes,
  or it is `unrecognized_critical_extension`. Name and policy constraints are not among them.
- **PATH-005** Every certificate above the end entity MUST be marked CA and within its path length
  (`chain_incomplete`), and allow certificate signing if it restricts key usage (`key_usage_mismatch`). A
  chain has at least an end entity and a root.
- **PATH-006** Every link's signature MUST verify under the next certificate's key, or it is
  `signature_invalid`. `go/tipki` admits ECDSA with SHA-256 or SHA-384 on P-256, P-384, brainpoolP256r1 and
  brainpoolP384r1. `rust/ti-pki` also admits RSA, for roots of the TI's past. This difference is
  deliberate and fails closed, so the corpus leaves RSA fixtures out.

## Bundle

- **BUNDLE-001** A bundle is one JSON file: `format_version` 2, `label`, `anchor_sha256` as 64 hex digits, and
  in standard base64 with padding `roots`, `tsl`, `tsl_sig` and optionally `tsl_ocsp`, each with its `*_meta`
  of `fetched_at` in Unix seconds, `source` and the optional `etag`, `last_modified` and `max_age_secs`. No
  unknown or repeated field is taken, and a bundle without a signature is refused. Its age counts from the
  older `fetched_at` of roots and TSL, which a copy does not reset.
- **BUNDLE-002** A bundle is for one anchor, and one for another is refused. It is not signed: every part is
  verified on use, and what it states only says what to verify.

## Corpus

[`testdata/path.json`](testdata/path.json) is every certificate of `rust/ti-pki/tests/pki` but those on RSA,
walked against all the others and the roots `rca1` and `rca7`, at three times under both models, and once
with its signature tampered. ti-pki writes it (`TI_PKI_BLESS=1`) and checks it, and `go/tipki` must judge the
same. [`testdata/bundle.json`](testdata/bundle.json) holds values, most of them malformed, on which both must
agree.

## Traceability

| Rule | Rust | Go |
|---|---|---|
| PATH-001 to 006 | `path_001_the_corpus_is_what_ti_pki_says` | `TestPATH001EveryPathIsJudgedAsInTiPki` |
| BUNDLE-001 | `bundle_001_values_are_read_or_refused_as_stated` | `TestBUNDLE001ValuesAreReadOrRefusedAsStated`, `FuzzParseBundle` |
| BUNDLE-002 | `Bundle::check_anchor` tests in `load/static_.rs` | `TestBUNDLE002AnotherEnvironmentsBundleIsRefused` |
