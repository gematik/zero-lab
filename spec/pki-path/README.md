# Certificate chains from a trust bundle

Language-neutral rules for building and checking a chain without a network, from the bundle file
`ti` writes. `rust/ti-pki` and `go/tipki` implement them, and [`testdata`](testdata) holds the two
together. It covers the path, the roots, the list, OCSP and the verdict they make together. A path that passes
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
- **PATH-007** A certificate with an EC public key that is not an uncompressed point does not parse. A signature
  with unused bits does not verify. A key and a signature have one encoding.

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
- **OCSP-002** Bytes outside what a signature covers are read strictly: a response's signature algorithm is a SEQUENCE
  and its signature has no unused bits, or it could not be decoded (`ocsp_unavailable`). Implementations MUST accept and
  refuse the same responses. Where their DER parsers differ on a malformed embedded certificate, the code of the refusal
  may differ.
- **OCSP-003** A request is one SHA-1 CertID, unsigned and without a nonce, the same bytes in both.
- **OCSP-005** A status error is repeated three times, then the responder rests for five minutes. Good and revoked
  results are reused for an hour at most, and to nextUpdate at most; unknown and errors never are.

OCSP is not air-gapped: the bundle makes the chain independent of the network, and revocation is asked online through
the caller's transport. Without a route to the responder there is no verification.

## Verdict

- **VALID-001** A certificate is judged in one order: chain, path and the end entity's requirements, the type its
  profile accepts, key admissibility, the CAs the list names, the types it lets a CA issue, a CA it revoked, revocation,
  and last the admission roles, only for a certificate valid otherwise (A_30046 (4)). Valid means no error, and a warning
  never decides.
- **VALID-002** Only the end entity's key is held to gemSpec_Krypt: P-256 and brainpoolP256r1 are admissible, RSA from
  3000 bits, RSA from 2048 bits a warning after 2025, and others are not.
- **VALID-003** A CA the list revoked still vouches for what it issued before the revocation, with a warning, and not
  for later certificates (Tab_PKI_271).

- **VALID-004** A responder is asked only about a certificate that has passed everything else. Its address is in the
  certificate, and a forged one must not be able to send a request anywhere.
- **VALID-005** A profile refuses a certificate whose detected type it does not accept, and one with no detectable type
  (`profile_type_mismatch`). What the caller names does not change what the certificate shows.
- **VALID-006** With a verified list, every CA of a chain must be one it names in accord, or revoked with a time, under a
  root, or it is `ca_not_in_tsl`. A CA supplied with a certificate gets no standing from a root's signature alone. The
  list names its own signer's CA as well, so a TSL signer is no exception.
- **VALID-007** With a verified list, a certificate's type must be among those the list states for its issuing CA, or it
  is `cert_type_ca_not_authorized` (TUC_PKI_007 step 9a). That is what makes a CA one for components, SMC-B, eGK or HBA:
  a certificate of a type its CA is not for fails, whatever its policies claim. A CA with no types stated may issue none.
  A TSL signer is judged by TUC_PKI_011 instead, since the list states no signer type for its CA.

## IDP-Dienst

`go/idpd` puts its keys to use as `ti-idpd` does.

- **IDPV-001** The discovery signer in the document's `x5c` passes before its key verifies anything. A refused
  certificate stops the client; a trusted one does not excuse a bad signature.
- **IDPV-002** `puk_idp_sig` carries its certificate in `x5c`, with the same key as the JWK, and that certificate passes
  on every fetch, before the key verifies a challenge or a token.
- **IDPV-003** There is no client or authenticator without trust material. Nothing downgrades a failure to a warning.
  One exception, decided by the maintainer (TASK-223): `ti-idpd`'s `trust::Unverified`, which `ti` offers as
  `--idp-unverified`, does not check at all. It serves an IDP outside the TI PKI (a reference implementation, the
  fake IDP of `ti`'s tests), is never a default, and marks the result: `verified` false and the warning
  `idp_certificates_unverified`. A check that runs and fails still stops the flow; `go/idpd` has no such mode.
- **IDPV-004** `puk_idp_enc` is published without a certificate, so nothing about its standing can be verified; this is a
  known gap, the same in `ti-idpd`. Its address comes from the verified discovery document, TLS carries it, and it must
  be a brainpoolP256r1 key with `use` `enc`.
- **IDPV-005** The check is the `idpd-sig` profile with hard-fail OCSP, against the bundle `ti pki trust export` writes.
  A bundle missing, invalid or too old (BUNDLE-003) refuses every certificate, and the last good one takes no part.
- **IDPV-006** The environment decides the anchors, and both sets are compiled in (decision-11): production trusts only
  GEM.RCA7 and GEM.TSL-CA3, test and reference only the TEST-ONLY pair. A missing or unknown environment does not start.
- **IDPV-007** The material may be downloaded instead of mounted, never both. Hosts are fixed per environment (a
  development environment takes the reference environment's) and redirects are refused. A list is taken only under the SHA-256 the HTTPS host publishes, since a signature over plain
  HTTP cannot say a list is the newest; it is not downloaded again while that hash stands (A_30044). Without a current
  `.ocsp` the signer's responder is asked. A client whose first download fails does not start.
- **IDPV-008** The download repeats in the background and a login only reads the copy in memory. A failed refresh keeps
  the copy until it is 24 h past its last good refresh or the list's `NextUpdate` has passed, then certificates are
  refused. An older list than the one in use is refused (TSLSIG-053).

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

[`testdata/validate.json`](testdata/validate.json) holds the verdicts of every fixture under every profile at three times,
under scripted revocation outcomes in both modes, with CAs revoked in the list, and a real SMC-B under the real list.

[`testdata/ocsp.json`](testdata/ocsp.json) holds every response fixture against four certificates, at eight times, online
and stapled, with three stores; a good response with each byte flipped; requests; and two real responses.

[`testdata/roots.json`](testdata/roots.json) holds crafted documents, gematik's real roots.json files from their
anchors, and every cross certificate against every root by the step that fails.

## Traceability

| Rule | Rust | Go |
|---|---|---|
| PATH-001 to 006 | `path_001_the_corpus_is_what_ti_pki_says` | `TestPATH001EveryPathIsJudgedAsInTiPki` |
| PATH-007 | `path_007_a_compressed_key_does_not_parse` | `TestPATH007ACompressedKeyDoesNotParse` |
| ROOTS-001 | `roots_001_the_corpus_is_what_ti_pki_says` | `TestROOTS001CraftedDocumentsAreWalkedAsInTiPki`, `FuzzParseRoots` |
| ROOTS-002 | `roots_001_the_corpus_is_what_ti_pki_says` | `TestROOTS002TheRealFilesReachTheRootsOfTiPki`, `TestROOTS002RSAIsForTheWalkAlone` |
| ROOTS-003 | `roots_001_the_corpus_is_what_ti_pki_says` | `TestROOTS003TheStepThatFailsIsThatOfTiPki` |
| ROOTS-004 | | `TestROOTS004ABundleForAnotherAnchorIsRefused` |
| OCSP-001 to 003 | `ocsp_001_the_corpus_is_what_ti_pki_says`, `ocsp_002_what_no_signature_covers_is_read_strictly` | `TestOCSP001EveryResponseIsJudgedAsInTiPki`, `TestOCSP002AFlippedByteIsJudgedAsInTiPki`, `TestOCSP003ARequestIsThatOfTiPki`, `TestOCSP004RealResponsesAreJudgedAsInTiPki`, `FuzzVerifyResponse` |
| OCSP-005 | unit tests in `ocsp.rs` | `TestOCSPStatusErrorsAreRepeatedThenTheResponderRests`, `TestOCSPResultsAreCachedWithinTheirBounds` |
| VALID-001 to 003 | `valid_001_the_corpus_is_what_ti_pki_says` | `TestVALID001EveryVerdictIsThatOfTiPki` |
| VALID-007 | `valid_007_the_tsl_states_the_types_a_ca_may_issue`, `valid_001_the_corpus_is_what_ti_pki_says` | `TestVALID007TheTypesTheListStates`, `TestVALID007TheRealListDecidesWhatACAMayIssue` |
| IDPV-001 to 008 | | `go/idpd/trust_test.go`, `go/idpd/fetch_test.go`, `go/tipki/fetch/trust_test.go`, `TestIDPV<n>…` |
| VALID-004 | `valid_004_no_responder_is_asked_for_a_certificate_that_failed` | `TestVALID004NoResponderIsAskedForACertificateThatFailed` |
| VALID-005 | `valid_005_a_profile_refuses_a_type_it_does_not_accept` | `TestVALID005AProfileRefusesATypeItDoesNotAccept` |
| VALID-006 | `valid_006_a_ca_the_verified_tsl_does_not_name_gives_no_standing` | `TestVALID006ACATheVerifiedListDoesNotNameGivesNoStanding`, `TestVALID006ACAUnderTheRealList` |
| BUNDLE-001 | `bundle_001_values_are_read_or_refused_as_stated` | `TestBUNDLE001ValuesAreReadOrRefusedAsStated`, `FuzzParseBundle` |
| TSLSIG-053 | `bundle_003_the_tsl_corpus_is_what_ti_pki_says` | `TestTSLThePublishedListsReadAsInTiPki`, `TestTSLSIG053ANumberBelowTheMinimumIsRefused` |
| TSLSIG-060 | unit tests in `tsl_signature.rs` | `TestTSLSIG060AnAnnouncedAnchorIsWarnedOf` |
| BUNDLE-003 | `bundle_003_the_tsl_corpus_is_what_ti_pki_says` | `TestBUNDLE003ABundleTooOldIsRefused`, `TestTSLThePublishedListsReadAsInTiPki` |
| BUNDLE-002 | `Bundle::check_anchor` tests in `load/static_.rs` | `TestBUNDLE002AnotherEnvironmentsBundleIsRefused` |
