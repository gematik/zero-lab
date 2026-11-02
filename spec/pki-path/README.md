# Certificate chains from a trust bundle

Language-neutral rules for building and checking a chain without a network, from the bundle file
`ti` writes. `rust/ti-pki` and `go/tipki` implement them, and [`testdata`](testdata) holds the two
together. It covers the path, the roots, the list and OCSP; putting them together into one verdict is the next stage
(TASK-176). A path that passes
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
  `signature_invalid`. The admitted algorithms are ECDSA on P-256 and brainpoolP256r1 with SHA-256, ECDSA on P-384
  and brainpoolP384r1 with SHA-384, and RSA PKCS#1 v1.5 and RSA-PSS with SHA-256, SHA-384 or SHA-512. No other
  pair of key and hash verifies.

## Roots

- **ROOTS-001** A roots.json is an array of entries, or an object with that array under `roots`. An entry has
  `cert`, and may have `cn`, `prev` and `next`, in standard base64; other fields are ignored. An empty list,
  or an entry whose root does not parse, refuses the file. A cross certificate is decoded only when reached,
  and an empty string is no link.
- **ROOTS-002** The walk starts at the anchor, which MUST be in the file. It follows `next`, then `prev`, and
  imports each root whose link passes ROOTS-003. A link that fails ends that direction without failing the
  load, so a download can only add roots that chain to the anchor. The algorithms are those of PATH-006: the
  TI's roots alternate between ECC and RSA, so the walk must pass through GEM.RCA6 and GEM.RCA9.
- **ROOTS-003** Importing a root on a cross certificate takes the seven checks of A_28419, stopping at the first
  that fails: signed by the trusted root, valid now, named `GEM.RCA<n>`, and with the subordinate's subject
  key identifier, common name and public key, and the subordinate's self-signature verifying under it.
- **ROOTS-004** The roots of a bundle are those of its `roots`, walked from the anchor it was exported for.

## OCSP

- **OCSP-001** A response counts only if a single response carries the certificate's CertID, an authorized
  responder signed it (the issuing CA, a delegate it certified with id-kp-OCSPSigning, or a delegate of a CA of the
  same provider, by a store), its certHash hashes this very certificate, and it lies within the TUC_PKI_006 window;
  outside that the status is `unknown`. The errors are `ocsp_unavailable`, `ocsp_response_invalid` and
  `ocsp_responder_untrusted`.
- **OCSP-002** Bytes outside what a signature covers are read as strictly by `go/tipki` as its DER parser reads them,
  which is stricter in places than `rust/ti-pki`. No response MAY be accepted by `go/tipki` that `rust/ti-pki` refuses.
- **OCSP-003** A request is one SHA-1 CertID, unsigned and without a nonce, the same bytes in both.
- **OCSP-005** A status error is repeated three times, then the responder rests for five minutes. Good and revoked
  results are reused for an hour at most, and to nextUpdate at most; unknown and errors never are.

OCSP is not air-gapped: the bundle makes the chain independent of the network, and revocation is asked online through
the caller's transport. Without a route to the responder there is no verification.

## Bundle

- **BUNDLE-001** A bundle is one JSON file: `format_version` 2, `label`, `anchor_sha256` as 64 hex digits, and
  in standard base64 with padding `roots`, `tsl`, `tsl_sig` and optionally `tsl_ocsp`, each with its `*_meta`
  of `fetched_at` in Unix seconds, `source` and the optional `etag`, `last_modified` and `max_age_secs`. No
  unknown or repeated field is taken, and a bundle without a signature is refused. Its age counts from the
  older `fetched_at` of roots and TSL, which a copy does not reset.
- **BUNDLE-002** A bundle is for one anchor, and one for another is refused. It is not signed: every part is
  verified on use, and what it states only says what to verify.
- **BUNDLE-003** A bundle whose age has reached 24 h is refused. Otherwise its roots come from the walk, and its
  CAs from a list verified as in [`spec/tsl-detached`](../tsl-detached/README.md), each kept only if a root
  signed it directly. The list is a directory and adds no trust. A list older than the one in use is refused
  (TSLSIG-053), so the caller keeps the state of the list across restarts.

## Corpus

[`testdata/path.json`](testdata/path.json) is every certificate of `rust/ti-pki/tests/pki`, walked against all the
others and the roots `rca1`, `rca7` and `rca-rsa`, at three times under both models, and once
with its signature tampered. ti-pki writes it (`TI_PKI_BLESS=1`) and checks it, and `go/tipki` must judge the
same. [`testdata/bundle.json`](testdata/bundle.json) holds values, most of them malformed, on which both must
agree.

[`testdata/tsl.json`](testdata/tsl.json) holds what ti-pki reads from the three published lists at their capture
time, as hashes of its services and CAs, and which CAs it keeps, and `go/tipki` must keep the same.
[`spec/tsl-detached`](../tsl-detached/CONFORMANCE.md) has its own corpus.

[`testdata/ocsp.json`](testdata/ocsp.json) holds every response fixture against four certificates, at eight times, online
and stapled, with three stores; a good response with each byte flipped; requests; and two real responses.

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
| OCSP-001 to 003 | `ocsp_001_the_corpus_is_what_ti_pki_says` | `TestOCSP001EveryResponseIsJudgedAsInTiPki`, `TestOCSP002AFlippedByteIsJudgedAsInTiPki`, `TestOCSP003ARequestIsThatOfTiPki`, `TestOCSP004RealResponsesAreJudgedAsInTiPki`, `FuzzVerifyResponse` |
| OCSP-005 | unit tests in `ocsp.rs` | `TestOCSPStatusErrorsAreRepeatedThenTheResponderRests`, `TestOCSPResultsAreCachedWithinTheirBounds` |
| BUNDLE-001 | `bundle_001_values_are_read_or_refused_as_stated` | `TestBUNDLE001ValuesAreReadOrRefusedAsStated`, `FuzzParseBundle` |
| TSLSIG-053 | `tsl_001_the_corpus_is_what_ti_pki_says` | `TestTSLThePublishedListsReadAsInTiPki`, `TestTSLSIG053ANumberBelowTheMinimumIsRefused` |
| TSLSIG-060 | unit tests in `tsl_signature.rs` | `TestTSLSIG060AnAnnouncedAnchorIsWarnedOf` |
| BUNDLE-003 | `tsl_001_the_corpus_is_what_ti_pki_says` | `TestBUNDLE003ABundleTooOldIsRefused`, `TestTSLThePublishedListsReadAsInTiPki` |
| BUNDLE-002 | `Bundle::check_anchor` tests in `load/static_.rs` | `TestBUNDLE002AnotherEnvironmentsBundleIsRefused` |
