# Certificate chains from a trust bundle

Language-neutral rules for building and checking a chain without a network, from the bundle file
`ti` writes. `rust/ti-pki` and `go/tipki` implement them, and [`testdata`](testdata) holds the two
together. It covers the path and the roots: the TSL and OCSP are later stages (TASK-176). A path that passes
is not yet a certificate to trust.

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

## Roots

- **ROOTS-001** A roots.json is an array of entries, or an object with that array under `roots`. An entry has
  `cert`, and may have `cn`, `prev` and `next`, in standard base64; other fields are ignored. An empty list,
  or an entry whose root does not parse, refuses the file. A cross certificate is decoded only when reached,
  and an empty string is no link.
- **ROOTS-002** The walk starts at the anchor, which MUST be in the file. It follows `next`, then `prev`, and
  imports each root whose link passes ROOTS-003. A link that fails ends that direction without failing the
  load, so a download can only add roots that chain to the anchor. RSA with SHA-256 is admitted here alone,
  because the TI's roots alternate between ECC and RSA and the walk must pass through GEM.RCA6 and GEM.RCA9.
- **ROOTS-003** Importing a root on a cross certificate takes the seven checks of A_28419, stopping at the first
  that fails: signed by the trusted root, valid now, named `GEM.RCA<n>`, and with the subordinate's subject
  key identifier, common name and public key, and the subordinate's self-signature verifying under it.
- **ROOTS-004** The roots of a bundle are those of its `roots`, walked from the anchor it was exported for.

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

[`testdata/roots.json`](testdata/roots.json) holds crafted documents, gematik's real roots.json files from their
anchors, and every cross certificate against every root by the step that fails.

## Traceability

| Rule | Rust | Go |
|---|---|---|
| PATH-001 to 006 | `path_001_the_corpus_is_what_ti_pki_says` | `TestPATH001EveryPathIsJudgedAsInTiPki` |
| ROOTS-001 | `roots_001_the_corpus_is_what_ti_pki_says` | `TestROOTS001CraftedDocumentsAreWalkedAsInTiPki`, `FuzzParseRoots` |
| ROOTS-002 | `roots_001_the_corpus_is_what_ti_pki_says` | `TestROOTS002TheRealFilesReachTheRootsOfTiPki`, `TestROOTS002RSAIsForTheWalkAlone` |
| ROOTS-003 | `roots_001_the_corpus_is_what_ti_pki_says` | `TestROOTS003TheStepThatFailsIsThatOfTiPki` |
| ROOTS-004 | | `TestROOTS004ABundleForAnotherAnchorIsRefused` |
| BUNDLE-001 | `bundle_001_values_are_read_or_refused_as_stated` | `TestBUNDLE001ValuesAreReadOrRefusedAsStated`, `FuzzParseBundle` |
| BUNDLE-002 | `Bundle::check_anchor` tests in `load/static_.rs` | `TestBUNDLE002AnotherEnvironmentsBundleIsRefused` |
