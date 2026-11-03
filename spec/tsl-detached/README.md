# TSL verification by the detached signature: requirements and design

Language-neutral specification for authenticating the gematik Trust-service Status List
(TSL) through the detached signature file the TSL service publishes next to it, and for
taking the TSL signer's status from the OCSP response file published with it. It is the
only way a list is authenticated; it replaced part A (XML and signature) of
[`spec/tsl-xmldsig`](../tsl-xmldsig/README.md), which is withdrawn. Parts B to G of that
document (signer, signer status, update, trust anchor, CA status, general)
apply unchanged to the signer and the list this document delivers. An implementation
built from both documents alone, checked against the corpus of
[CONFORMANCE.md](CONFORMANCE.md), is conformant.

Each rule has exactly one identifier `TSLDET-nnn`. Tests cite these identifiers; the
gematik requirements map onto them in [Requirement mapping](#requirement-mapping). The
key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

- [Scope](#scope)
- [References](#references)
- [File profile](#file-profile)
- [Rules](#rules)
  - [A. The signature file](#a-the-signature-file)
  - [B. Download](#b-download)
  - [C. Signer status from the published response](#c-signer-status-from-the-published-response)
  - [D. The rest of the verification](#d-the-rest-of-the-verification)
- [Result codes](#result-codes)
- [Algorithm](#algorithm)
- [Requirement mapping](#requirement-mapping)
- [Deviations](#deviations)
- [Security considerations](#security-considerations)

## Scope

In scope:

- the TSL(ECC-RSA) of the environments PU, RU and TU and the three files the TSL service
  publishes for the automated download (gemSpec_TSL 6.3.1.3): the list (`.xml`), the
  detached signature of the whole list file (`.sig`) and the OCSP response for the TSL
  signer (`.ocsp`);
- the verification of that signature over the list's bytes and the use of the published
  status response;
- how the three files are fetched together with the hash compare of the HTTPS download
  point.

Out of scope, because `spec/tsl-xmldsig` owns them: the signer certificate's profile and
anchor (part B), the status query over the network (part C), the update rules (part D),
the anchor change (part E), the CA status (part F) and the general rule (part G). Out of
scope entirely: the enveloped XML signature inside the list, which stays there as
content and is not evaluated; the TSL(RSA) and its RSASSA-PSS signature; the BNetzA-VL.

## References

| Short name | Document |
|---|---|
| gemSpec_TSL | [gemSpec_TSL V1.25.0](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_TSL/gemSpec_TSL_V1.25.0.html), 6.3.1.3 "Automatisierbarer TSL-Download aus dem Internet", A_21175 to A_21182 |
| gemSpec_PKI | [gemSpec_PKI V2.28.0](https://gemspec.gematik.de/downloads/gemSpec/gemSpec_PKI/gemSpec_PKI_V2.28.0.html), 8.2.6 (A_30044), TUC_PKI_001, TUC_PKI_006, TUC_PKI_011, TUC_PKI_012 |
| TR-03111 | BSI TR-03111 V2.10 Elliptic Curve Cryptography, 5.2.1 (plain format), 5.2.2 (X9.62 format: `ECDSA-Sig-Value`) |
| Design note | [gematik examples-TelematikInterfaces, tslService/detachedSignature](https://github.com/gematik/examples-TelematikInterfaces/tree/master/tslService/detachedSignature): why the file exists, agreed with the BSI: a consumer need not decode the XML or evaluate the complex XMLDSig, which an attacker may have modified |
| RFC 5280, RFC 6960 | X.509, OCSP |
| spec/tsl-xmldsig | the rules this document relies on, `TSLSIG-nnn` |

## File profile

What gematik publishes, decoded on 2026-11-01 from the files of PU, RU and TU (their
hashes are in [`testdata/README.md`](testdata/README.md)):

```text
.sig  ::= SEQUENCE {
            SEQUENCE { OBJECT IDENTIFIER ecdsa-with-SHA256 (1.2.840.10045.4.3.2) },
            BIT STRING (0 unused bits) {
              SEQUENCE { INTEGER r, INTEGER s }        -- ECDSA-Sig-Value, TR-03111 5.2.2
            },
            Certificate                                -- the TSL signer, C.TSL.SIG
          }
.ocsp ::= OCSPResponse                                 -- RFC 6960, DER
```

The `.sig` of PU is 712 bytes, those of RU and TU 763 and 762; the signer is "TSL Signing
Unit 6" under GEM.TSL-CA3 (PU) and "TSL Signing Unit 12 TEST-ONLY" under GEM.TSL-CA28
TEST-ONLY (RU, TU), with brainpoolP256r1 keys. The `.ocsp` files are responses of the TSL
signer CA's delegated responder with the responder certificate included, produced within
the hour (A_21181). A_21179 names the signature value as the format of BSI TR-03111
5.2.2, the DER `ECDSA-Sig-Value`, which is what the published files carry.

The files are published on the CRL host of the environment over plain HTTP (A_21175,
A_21176); the URIs are in A_21182 and repeated in [B. Download](#b-download). The HTTPS
download points of gemSpec_PKI 8.2.6 serve the list and its `.sha2` only.

## Rules

Result codes are named in [Result codes](#result-codes). Every failed check of part A is
`detached_signature_error` unless another code is given; the detail names the cause.

### A. The signature file

| ID | Rule | Code |
|---|---|---|
| TSLDET-001 | The `.sig` file MUST be at most 8192 bytes and strict DER: exactly one SEQUENCE of three elements, no bytes after it. Lengths MUST be checked before an element is decoded. | `detached_signature_error` |
| TSLDET-002 | Element 1 MUST be the AlgorithmIdentifier `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) with absent parameters. `rsaPSS` (the TSL(RSA)) and every other algorithm MUST be rejected. | `detached_signature_error` |
| TSLDET-003 | Element 2 MUST be a BIT STRING with zero unused bits whose content is a DER `ECDSA-Sig-Value` (SEQUENCE of two INTEGERs) with `0 < r < n` and `0 < s < n` for the brainpoolP256r1 order `n`, in minimal DER encoding (TR-03111 5.2.2). The 64-byte plain form `r ‖ s` of 5.2.1 MUST be rejected. | `detached_signature_error` |
| TSLDET-004 | Element 3 MUST be a parsable DER X.509 certificate: the signer, not yet authenticated. Its public key MUST be on brainpoolP256r1 (as TSLSIG-012). | `tsl_cert_extraction_error` |
| TSLDET-005 | The signature MUST verify with the signer's public key, ECDSA with SHA-256, over the complete bytes of the `.xml` file as received, after transport decoding (content coding removed) and before any parsing. No canonicalization and no transformation of any kind is applied. | `detached_signature_error` |
| TSLDET-006 | A list MUST be at most 16 MiB, checked before it is hashed. After successful verification it MUST be read from exactly the verified bytes. The enveloped `ds:Signature` element inside them is content and MUST be ignored, never verified or required. | `tsl_not_wellformed` |

### B. Download

| ID | Rule | Code |
|---|---|---|
| TSLDET-010 | `.xml`, `.sig` and `.ocsp` MUST be fetched from the configured automated download point of the environment (A_21182), the same origin, as one set, never from addresses inside a TSL. Before the set is fetched, the `.sha2` of the configured HTTPS download point MUST be compared with the hash of the current list (A_30044 (2), TSLSIG-050); the fetched `.xml` MUST match the published hash. Without a readable hash the list MUST NOT be taken from a plain-HTTP origin, only from the HTTPS download point. A plain-HTTP origin gets no validators for the list, and its "not modified" MUST NOT be believed: it would renew the list's age without authentication. A load failure is retried and reported by the loader; it has no result code. |
| TSLDET-011 | Plain `http://` is acceptable for the automated download point, which A_21175 mandates: trust comes from the signature and the hash, never from the transport. A gzip content coding is removed before verification. | |
| TSLDET-012 | The automated download points of A_21182: PU `http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.{xml,sig,ocsp}`; RU `http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.{xml,sig,ocsp}`; TU `http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test.{xml,sig,ocsp}`. The `.sig` and `.ocsp` URIs are the `.xml` URI with its suffix replaced. | |
| TSLDET-013 | A list without a signature file that verifies MUST NOT be used; there is no other way to authenticate it. Because the files travel over plain HTTP and may be cached before they are verified, a set that fails verification MUST be fetched once more without validators before the failure stands (A_21177). That MUST NOT discard the set in hand: it stays available for an origin that fails, at its real age. A fault of the implementation's own cache is reported as such, not as a missing file. | `detached_signature_error` |
| TSLDET-014 | When the plain-HTTP origin is unreachable, or serves bytes that do not match the published hash (it may lag by up to an hour, A_21178), the load fails and is retried, and the list in hand MUST stay in use within its limits. The list MUST NOT be taken from the HTTPS point in that case: its signature is not available, and it would replace a set that verifies with one that does not. | |
| TSLDET-015 | A cached `.sig` MAY be used at any age when its origin cannot be reached: it verifies over the list or it does not. A list the HTTPS hash keeps confirming therefore stays usable while the plain-HTTP host is down. A stale `.ocsp` MUST NOT be used. | |

### C. Signer status from the published response

| ID | Rule | Code |
|---|---|---|
| TSLDET-020 | A supplied `.ocsp` MUST be verified like a queried response: signed by the signer's CA or by a responder that CA certified for OCSP signing (TSLSIG-040), with a certHash matching the signer, answering for the signer's serial under its CA (TSLSIG-041). Its `producedAt` MUST NOT be later than the validation time plus the clock tolerance, and `thisUpdate ≤ t`. Status `revoked` or `unknown`, a missing or mismatching certHash, an unauthorized responder, a response for another certificate, or an unparsable response MUST prevent the use of the list. | codes of TSLSIG-040 to 042 |
| TSLDET-021 | A supplied `.ocsp` whose `producedAt` is more than 2 hours before the validation time (A_21181 renews it hourly) MUST NOT be taken as `good`: the status is then "not queried" (TSLSIG-043), the warning's detail names the age and the maximum, and a network query (TSLSIG-040) MAY replace it. A verified `revoked` stops the use of the list at any age. | `no_ocsp_check` (warning), `cert_revoked` |
| TSLDET-022 | Without a `.ocsp` and without a network transport the status is not queried (TSLSIG-043). | `no_ocsp_check` (warning) |
| TSLDET-023 | A consumer validating at a time other than the current one MUST NOT use a published `.ocsp`: it says nothing about that time. The status is then not queried. | `no_ocsp_check` (warning) |

### D. The rest of the verification

| ID | Rule |
|---|---|
| TSLDET-030 | Parts B to G of `spec/tsl-xmldsig` apply unchanged: the signer of TSLDET-004 is checked by TSLSIG-030 to 035 against the anchor resolved by part E, the list of TSLDET-006 by parts D and F, and everything fails closed with one result code (TSLSIG-080). |

## Result codes

| Code | No. | Kind | Rules |
|---|---|---|---|
| `detached_signature_error` | – | error | 001, 002, 003, 005, 013 |
| `tsl_cert_extraction_error` | 1002 | error | 004 |
| `tsl_not_wellformed` | 1011 | error | 006 |
| `no_ocsp_check` | 1039 | warning | 021, 022, 023 |
| the codes of TSLSIG-040 to 042 | | error | 020 |
| the codes of parts B to G of `spec/tsl-xmldsig` | | | 030 |

`detached_signature_error` is this specification's own code: Tab_PKI_274 has
`SE_1013_XML_SIGNATURE_ERROR` for the enveloped signature and nothing for a detached one.
Everything else uses the codes of `spec/tsl-xmldsig`.

## Algorithm

```text
update(state, transport, t):
  hash ← transport.get(url_sha2 of the HTTPS download point)        # TSLDET-010
  if state.tsl ≠ ∅ and hash = state.hash:
      return check_grace(state.tsl, t)                               # TSLSIG-054
  if hash unreadable: xml ← transport.get(url_xml of the HTTPS point)  # TSLDET-010
  else:
    xml ← transport.get(url_xml of the automated download point)       # TSLDET-010, 012
    if unreachable or sha256(xml) ≠ hash: load failure, retry;
      keep the list in hand                                            # TSLDET-014
  sig ← transport.get(url_sig), a cached one if unreachable           # TSLDET-012, 015
  ocsp ← transport.get(url_ocsp)                                       # TSLDET-012
  signer ← verify_detached(xml, sig)                                  # A
  on any failure: expire the set, fetch it once more, verify again     # TSLDET-013
  anchor, way ← resolve_anchor(signer, …)                             # TSLSIG part E
  check signer under anchor, validity, KU, EKU, profile               # TSLSIG-031..035
  status ← supplied_status(signer, anchor, ocsp, t)                   # C
  if status = stale and transport ≠ ∅: check_ocsp(signer, t)          # TSLSIG-040..042
  tsl ← parse(xml)                                                     # TSLDET-006
  check_sequence(tsl, state); check_grace(tsl, t)                      # TSLSIG-053, 054
  announcement, replace CA set                                         # TSLSIG-051, 052, 060..

verify_detached(xml, sig):
  check len(sig) ≤ 8192; decode SEQUENCE { alg, bits, cert }, no trailing bytes   # TSLDET-001
  check alg = ecdsa-with-SHA256 without parameters                              # TSLDET-002
  check bits has 0 unused bits; signature ← DER ECDSA-Sig-Value, 0 < r, s < n   # TSLDET-003
  signer ← parse X.509(cert); check key on brainpoolP256r1                      # TSLDET-004
  check ECDSA-SHA256(signer.key, xml, signature)                                # TSLDET-005
  return signer

supplied_status(signer, anchor, ocsp, t):
  if ocsp = ∅: warn no_ocsp_check; return none                                   # TSLDET-022
  result ← verify_ocsp(ocsp, signer, anchor, t, max_age = 2 h)                 # TSLDET-020
  if result = too old:
    if its status as of its own producedAt is revoked: fail cert_revoked       # TSLDET-021
    warn no_ocsp_check with the age; return stale                              # TSLDET-021
  if result ∉ {good}: fail with the code of TSLSIG-041/042                     # TSLDET-020
  return result
```

The signature of part A is checked before the signer's certificate (parts B and E), as
`spec/tsl-xmldsig` does; the order may differ if the result is the same (TIP1-A_2174).

## Requirement mapping

| Document | Requirement | TSLDET |
|---|---|---|
| gemSpec_TSL | A_21175 (download point, HTTP only, fallback for Konnektors) | 011, 012 |
| | A_21176 (same host as the CRL) | 012 |
| | A_21177 (three files, `.xml` and `.sig` consistent) | 010 |
| | A_21178 (the list on the internet point within an hour) | 010 |
| | A_21179 (the detached signature file and its structure) | 001 to 005 |
| | A_21181 (the OCSP response file, hourly) | 020, 021 |
| | A_21182 (URIs per environment) | 012 |
| gemSpec_PKI | A_30044 (1) configured addresses, (2) hash compare, (3) OCSP of the signer, (4) retries | 010, 020, 021 |
| | GS-A_4650 TUC_PKI_011 (signer certificate) | 004, 030 |
| | GS-A_4651 TUC_PKI_012 (XML signature) | replaced by 001 to 006, see [Deviations](#deviations) |
| | GS-A_4642 TUC_PKI_001 steps 3 and 5 to 7 | 030 |
| | GS-A_4657 TUC_PKI_006 (OCSP response check) | 020 |
| TR-03111 | 5.2.2 (X9.62 format, `ECDSA-Sig-Value`) | 003 |

## Deviations

From gemSpec_PKI: **TUC_PKI_012 is replaced.** gemSpec_PKI 8.2.6 / A_30044 tells internet
consumers to run TUC_PKI_001, whose step 4 is the XML signature check, and gemSpec_TSL
6.3.1.3 names the three files a fallback for Konnektors. Verifying by `.sig` and `.ocsp`
is the same check cryptographically (same signer, same anchor, same OCSP, the exact bytes
that are hashed and compared) but not the method the requirement names. The maintainer
decided to take it (2026-11-01, TASK-166) ahead of a change to the specifications; the
request for change is backlog doc-3 (TASK-167). gematik's design note gives the reason the
file exists, agreed with the BSI: it is safer to verify than the XMLDSig.

From gemSpec_PKI 8.2.6: the list and the signature come from the CRL host of A_21182 rather
than only the HTTPS points it names, because `.sig` and `.ocsp` are published nowhere else.

## Security considerations

- **Exact bytes.** The signature covers the bytes that are hashed, compared and later
  parsed (TSLDET-005, 006). There is no canonicalization and no transform between
  verification and use, so the signature wrapping and canonicalization classes of
  `spec/tsl-xmldsig` do not exist on this path; a parser differential cannot move
  content out from under the signature, because the signature is over the input, not a
  tree.
- **Same trust.** The signer is authenticated exactly as for the enveloped signature
  (parts B and E of `spec/tsl-xmldsig`); no new anchor, key or responder enters.
- **Transport.** The files travel over plain HTTP. Integrity and origin follow from the
  signature and the hash from HTTPS; the plain origin is asked for the list only under
  that hash and cannot confirm a list with "not modified" (TSLDET-010), so it can withhold
  or delay, never inject, and cannot renew the age of material.
- **Consistency.** `.xml` and `.sig` of different states fail part A and the set is
  fetched again (TSLDET-013). A verifier never accepts a list under another's signature.
- **Availability.** `.sig` is published only over plain HTTP on the CRL host (A_21175). A
  network that blocks it cannot authenticate a new list, even though HTTPS serves it: the
  list in hand stays in use while the HTTPS hash confirms it (TSLDET-015), and ages out by
  its hard expiry once a new one is published. Each publication also opens a window of up
  to an hour (A_21178) in which the new list cannot be taken yet (TSLDET-014). Publishing
  `.sig` and `.ocsp` on the HTTPS points, as doc-3 asks, removes both.
- **Replay and downgrade.** Unchanged: the sequence number and `NextUpdate` rules of part
  D reject an older signed list, and the algorithm is a single fixed combination
  (TSLDET-002, 003).
- **Stale status.** A response older than its maximum is not taken as `good`, because a
  stale `good` is no evidence; the network query of part C may replace it. A signed
  `revoked` stops the list at any age, since a consumer may not have seen it while it was
  fresh (TSLDET-021). A fresh response that is wrong fails closed (TSLDET-020).
- **Parser surface.** The `.sig` parser reads a bounded DER structure of three fields; it
  and the OCSP parser are fuzzed. The XML parser reads only signed bytes and is off the
  trust path.

## Licence

Copyright 2026 gematik GmbH. EUPL-1.2, see [rust/LICENSE](../../rust/LICENSE). The test
data under `testdata/` is gematik's published trust material (PU) and TEST-ONLY material
(RU, TU), see [`testdata/README.md`](testdata/README.md).
