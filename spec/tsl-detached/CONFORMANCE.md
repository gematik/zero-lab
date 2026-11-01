# TSL verification by the detached signature: conformance

How an implementation of [README.md](README.md) proves conformance: the corpus, its
manifest and the command-line contract, modelled on
[`spec/tsl-xmldsig/CONFORMANCE.md`](../tsl-xmldsig/CONFORMANCE.md).

## Corpus

```text
testdata/
  README.md              capture time, URLs, hashes and signers of the published sets
  manifest.json          every fixture, its expected result and the rules it covers
  prod/                  ECC-RSA_TSL.{xml,sig,ocsp} of PU, captured together
  ref/                   ECC-RSA_TSL-ref.{xml,sig,ocsp} of RU
  test/                  ECC-RSA_TSL-test.{xml,sig,ocsp} of TU
  derived/               negative fixtures derived from the captured files by tool/derive.py
tool/
  derive.py              the derivation (standard library only; python3 -I tool/derive.py testdata)
```

The published sets are committed as captured, with their capture time, so that the
`.ocsp` files verify at that time (TSLDET-020) and are stale after it (TSLDET-021).
Derived fixtures are deterministic functions of the captured files; `derive.py` is their
documentation and regenerates them bit for bit.

## Manifest

`testdata/manifest.json` is an array; one object per fixture:

```json
{
  "path": "ref/ECC-RSA_TSL-ref.xml",
  "signature": "ref/ECC-RSA_TSL-ref.sig",
  "signer_status": "ref/ECC-RSA_TSL-ref.ocsp",
  "producer": "gematik-ru",
  "rules": ["TSLDET-005", "TSLDET-020", "TSLDET-030"],
  "time": "2026-11-01T16:47:42Z",
  "env": "nonprod",
  "expect": {
    "result": "valid",
    "code": null,
    "rule": null,
    "warnings": [],
    "signer_serial": "06",
    "sequence_number": 10717
  }
}
```

| Field | Meaning |
|---|---|
| `path` | the list, relative to `testdata/` |
| `signature` | the `.sig` file |
| `signer_status` | the `.ocsp` file, or absent: the status is not supplied |
| `producer` | `gematik-pu`, `gematik-ru`, `gematik-tu`, or `derive.py` |
| `rules` | the TSLDET identifiers this fixture covers |
| `time` | the validation time `t`; the capture time for the published sets |
| `env` | `prod` or `nonprod`: which TSL signer anchors apply |
| `expect.result` | `valid` or `invalid` |
| `expect.code`, `expect.rule` | the single result code and the rule of an invalid fixture |
| `expect.warnings` | the warnings that must be present, and no others |
| `expect.signer_serial`, `expect.sequence_number` | values the implementation must report for a valid list |

A conformance test fails when a manifest entry names a rule that README.md does not
define, or when a rule of README.md is named by no entry and no test of the
implementation. Rules of part B (download) are proven by tests of the loader against a
scripted transport, not by fixtures.

## Command-line contract

```console
verifier verify-detached --manifest-entry '<json object>' --testdata <dir>
```

One JSON object on stdout, exit 0 whatever the verdict (non-zero only when it could not
run):

```json
{ "result": "invalid", "code": "detached_signature_error", "rule": "TSLDET-005",
  "detail": "the signature value does not verify", "warnings": [],
  "signer_serial": null, "sequence_number": null }
```

## Conformance

An implementation conforms when:

1. it matches every manifest entry: result, code, rule, the warnings, and the further
   `expect` values;
2. every TSLDET rule is covered by at least one manifest entry or named test;
3. it verifies the current published sets of PU, RU and TU from the automated download
   points, with the status taken from their `.ocsp` files.
