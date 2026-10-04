# TSL signature verification: conformance

How an implementation of [README.md](README.md) proves conformance: the test corpus, its
manifest, the command-line contract every implementation provides, and the
interoperability matrix.

## Corpus

```text
testdata/
  manifest.json          every fixture, its expected result and the rules it covers
  c14n/                  canonicalization inputs and expected outputs
    spec/                examples of C14N 1.0 §3 and Exc-C14N
    w3c/                 merlin-exc-c14n-one, merlin-c14n-three (with their README)
    stress/              generated: many namespaces, xml:lang, non-ASCII, &#xD;, empty
                         elements, attribute order
  tsl/
    real/                published TSLs of PU, RU, TU (current and older sequence numbers)
    gemlibpki/           fixtures of gematik ref-GemLibPki 5.0.2 (NOTICE, SHA256SUMS)
    <generator>/         fixtures produced by one generator (see Generators)
  pki/                   anchors, root CAs, certificates and keys the fixtures use;
                         TEST-ONLY material only
interop/
  <generator>/           generator and verifier of one implementation
  matrix.md              result of the last interoperability run
```

Fixtures are committed; generators are reproducible from a pinned tool version. Keys of
generated fixtures are generated per run and committed only where a fixture must be
re-signed later (the GemLibPki signer keys, published by gematik as test material).

## Manifest

`testdata/manifest.json` is an array; one object per fixture:

```json
{
  "path": "tsl/gemlibpki/valid/TSL_default.xml",
  "kind": "tsl",
  "producer": "gemlibpki-5.0.2",
  "rules": ["TSLSIG-010", "TSLSIG-016", "TSLSIG-020", "TSLSIG-064"],
  "time": "2026-04-10T00:00:00Z",
  "env": "nonprod",
  "anchors": { "embedded": "pki/gemlibpki/GEM.TSL-CA28-TEST-ONLY.der" },
  "state": null,
  "ocsp": "offline",
  "expect": {
    "result": "valid",
    "code": null,
    "warnings": ["no_ocsp_check"],
    "anchor_way": "roots",
    "sequence_number": 420127
  },
  "note": "CA51 is not embedded; it is found under GEM.RCA5 TEST-ONLY of roots-nonprod.json"
}
```

| Field | Meaning |
|---|---|
| `path` | fixture, relative to `testdata/` |
| `kind` | `tsl` (full verification), `c14n` (canonicalization: `expected` names the output file), `xml` (part A only, against `anchors.signer_key`) |
| `producer` | generator and version, or `gematik-pu`, `gematik-ru`, `gematik-tu`, `gemlibpki-5.0.2`, `handmade` |
| `rules` | the TSLSIG identifiers this fixture covers |
| `time` | the validation time `t` |
| `env` | `prod` or `nonprod`: which roots.json and which TEST-ONLY rules apply |
| `anchors` | the embedded anchor; optionally an already announced anchor with activation time |
| `state` | stored state before the update (`id`, `sequence_number`, `hash`), or `null` |
| `ocsp` | `offline`, or the name of a scripted responder in `testdata/pki/ocsp/` |
| `expect.result` | `valid`, `invalid`, `no_update` |
| `expect.code` | the single result code of an invalid fixture |
| `expect.warnings`, `expect.reports` | warnings and reports (TSLSIG-061) that must be present, and no others |
| `expect.*` | further values the implementation must report (anchor way, sequence number, signer serial, CA count) |

A conformance test fails when a manifest entry names a rule that README.md does not
define, or when a rule of README.md is named by no entry and no test of the implementation.

## Command-line contract

Every implementation provides a verifier the matrix script can call:

```console
verifier verify --manifest-entry '<json object>' --testdata <dir>
```

It writes one JSON object to stdout and exits 0 whatever the verdict (non-zero only when
it could not run):

```json
{ "result": "invalid", "code": "xml_signature_error", "detail": "reference 1: digest mismatch",
  "warnings": [], "reports": [], "anchor_way": null, "sequence_number": null }
```

External tools that only verify XML signatures (xmlsec1, Santuario, signxml, .NET) take
part in the matrix for part A only: their verdict is `valid`/`invalid` against the
signer key, without codes.

## Generators

| Generator | Tools (pinned in its directory) | Produces |
|---|---|---|
| `gemlibpki` | Java 21, Maven, `de.gematik.pki:gemlibpki:5.0.2` (`TslSignerNonQes`, `TslModifier`) | profile-conformant TSLs from the GemLibPki templates: sequence, NextUpdate, StatusStartingTime, signer and anchor-change variants; re-signed GemLibPki fixtures |
| `santuario` | Java 21, Apache Santuario `xmlsec`, BouncyCastle | profile and out-of-profile signatures, XML negative cases |
| `python` | venv: lxml, xmlsec, signxml, cryptography | same |
| `xmlsec1` | libxmlsec1 with OpenSSL 3 | same |
| `dotnet` | .NET SDK, `System.Security.Cryptography.Xml.SignedXml` | same, as far as .NET signs ECDSA |
| `openssl` | `rust/ti-pki/tests/pki/generate.sh` | certificates for parts B, C, E: signer and CA profile violations, new TSL signer CAs under the test roots |

Each generator writes its fixtures and their manifest entries; `just xmldsig-corpus`
merges the entries into `manifest.json`. Every generator covers, where its tool can:
- valid signatures in the profile, brainpoolP256r1;
- out-of-profile signatures (P-256, RSA, RSASSA-PSS, inclusive C14N, PrefixList, comments,
  SHA-1/SHA-512 digests), expected `xml_signature_error`;
- the XML negative cases of README.md part A: content, digest, `SignedInfo` changed;
  references missing, added, swapped; XPath, XSLT, base64 transforms; two signatures,
  signature not last; signature wrapping variants; duplicate `Id`; DTD and entity
  declarations; `KeyInfo` certificate not matching `CertDigest`.

## Interoperability matrix

`just xmldsig-interop` regenerates the corpus and lets every verifier check every
fixture. `interop/matrix.md` records, per fixture, the manifest expectation and each
verifier's verdict. A difference between external tools and the manifest is explained in
the matrix (e.g. "xmlsec1 accepts inclusive C14N, out of profile here"); a difference
between a conforming implementation and the manifest is a defect.

## Conformance

An implementation conforms when:
1. it matches every manifest entry: result, code, required warnings and reports, and the
   further `expect` values;
2. every TSLSIG rule is covered by at least one manifest entry or named test;
3. its canonicalization output equals the expected output for every `c14n` entry;
4. it verifies the current published TSLs of PU, RU and TU.
