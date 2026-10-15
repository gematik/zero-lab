# Shared specifications

Language-neutral specifications for functions more than one implementation provides, or
that must be held to exact behaviour. An implementation built from a specification alone
and passing its corpus is conformant; neither the Rust nor the Go code is the
specification. Why and when a specification is needed is in
[docs/interop.md](../docs/interop.md#a-concise-shared-specification).

| Specification | Topic | Implementations |
|---|---|---|
| [tsl-xmldsig](tsl-xmldsig/README.md) | TSL signature verification and update | `rust/ti-xmldsig`, `rust/ti-pki` |
| [pkcs12](pkcs12/README.md) | PKCS#12 decoding and encoding | `rust/ti-pkcs12`, `go/pkcs12` |

## Writing a specification

One directory per topic, `spec/<topic>/`, modelled on `tsl-xmldsig` and `pkcs12`:

```text
spec/<topic>/
  README.md          the requirements
  CONFORMANCE.md     how an implementation proves conformance
  testdata/
    manifest.json    every fixture, its expected result code and the rules it covers
    …                fixtures (real artefacts and generated ones; TEST-ONLY keys only)
  interop/           one adapter per implementation, and matrix.md of the last run
  tool/              the generator and verifier, if the corpus is generated
```

`README.md` has these sections:

1. **Scope**: what is specified and what is not.
2. **References**: the RFCs and gemSpec documents, with versions.
3. **Profiles** where implementations may support subsets (for example modern and
   legacy).
4. **Rules**, grouped, each with exactly one identifier `TOPIC-nnn` (`TSLSIG-066`,
   `P12-036`), worded with MUST, SHOULD and MAY as in RFC 2119, and testable on its own.
5. **Result codes** every implementation returns, with the mapping to each
   implementation's errors, so verdicts compare exactly and not only as pass or fail.
6. **Algorithm**: the order in which the rules apply, where order matters.
7. **Requirement mapping** from gematik requirements (afo, TUC) to the rules.
8. **Deviations**: where a known implementation or version departs from a rule, and since
   when it is fixed.
9. **Security considerations**: what the rules protect against and what they do not.

`CONFORMANCE.md` describes the corpus and its manifest, the command-line or test contract
each implementation's adapter fulfils, how to run the interoperability matrix
(`interop/run.sh`), and the differences found in third-party implementations.

The specification states behaviour and limits, not code structure. Tests in each
implementation are named after the rules they prove
([docs/design/testing.md](../docs/design/testing.md#tests-name-the-requirement-they-prove)),
and a disagreement between implementations is fixed in the specification first.
