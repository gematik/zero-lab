# tipki

A Go library for the **public key infrastructure of the German Telematikinfrastruktur (TI)**: reading
what a certificate states, and deciding from a verified trust list whether to accept it. It uses the
standard library and `go/brainpool`, and performs no I/O of its own.

It covers:

- **Certificates:** certificate types, the admission extension and validation profiles, including
  certificates with Brainpool keys, which `crypto/x509` refuses.
- **Trust:** the TSL, verified by its detached signature, the roots it leads to, and chains checked
  against RFC 5280.
- **Revocation:** OCSP through a transport the caller supplies.
- **Identifiers:** the tables of gemSpec_OID, in package `oid`, as binary `x509.OID` values.

A [`Validator`](#validator) combines these into one verdict, under a [`Profile`](#profiles) for the
use at hand.

## Example

```go
cert, err := tipki.ParseCertificate(der)
if err != nil {
	return err
}

certType, ok := tipki.DetectCertificateType(cert)
if !ok {
	return errors.New("not a certificate type of the TI")
}

admission, err := tipki.Admission(cert)
if err != nil {
	return err
}
isArzt := slices.ContainsFunc(admission.ProfessionOIDs, oid.ProfArzt.Equal)
```

Reading a certificate does not make it trustworthy: only a `Validator` decides that.

## Profiles

A certificate type states what gemSpec_PKI requires of every certificate of that type. A **profile** is
a named overlay on a type for one use: which types it accepts, which roles it requires and how strictly
it treats revocation.

| Profile | Use | Accepts | Required role | Revocation |
|---------|-----|---------|---------------|------------|
| `dipag-vau-aut` | Digitale Patientenrechnung VAU | `C.FD.AUT` | `oid_dipag-vau` | hard-fail |
| `epa-vau-aut` | ePA Aktensystem VAU | `C.FD.AUT` | `oid_epa_vau` | hard-fail |
| `fd-tls-s` | Fachdienst TLS server | `C.FD.TLS-S` | none | hard-fail |
| `hci-aut` | Institution authentication (SMC-B, HSM-B) | `C.HCI.AUT` | any institution (Tab_PKI_403) | hard-fail |
| `idpd-sig` | IDP discovery document and token signing | `C.FD.SIG` | `oid_idpd` | hard-fail |
| `tsl-sig` | TSL signer | `C.TSL.SIG` | none | hard-fail |
| `zeta-guard-aut` | ZETA Guard | `C.FD.AUT` | `oid_zeta-guard` | hard-fail |

Two rules keep a profile from widening what is accepted:

- **Roles replace, they do not add.** The role check is any-of, so adding to the type's roles would
  accept more.
- **Revocation only tightens.** A profile can raise the mode an operator configured, never lower it. The
  exception is a configured `disabled`, which stays disabled; no profile asks for it.

`Profile.Check` reads only the certificate, and nothing it returns is a verdict on its chain or standing.

**Selection.** `SelectForCert` names the profile a certificate fits: a single profile matched on its role
wins, then the profile that owns the type by default, then the only one accepting the type. Ambiguity is
reported and never guessed. Selection reads unauthenticated content, so it only says which profile is
the right lens. When the use is known, name the profile instead.

## Validator

A `Validator` judges one certificate, following TUC_PKI_018. Build it from a profile, with a store loaded
from a verified bundle and an OCSP checker over your own transport:

```go
store, err := tipki.LoadTrustStore(bundle, tipki.AnchorProd, signerAnchors, now, 0, nil)
if err != nil {
	return err
}

validator := tipki.ProfileEpaVauAut.Validator(store, tipki.CertFdAut, tipki.RevocationHardFail)
result, err := validator.Validate(ctx, certs, now, tipki.NewOCSPChecker(transport))
if err != nil {
	return err
}
if !result.Valid {
	return fmt.Errorf("not accepted: %v", result.Errors)
}
```

`certs[0]` is the end entity, and the others are only candidates for the chain. Loading needs no network,
and a bundle older than 24 hours is refused. The last argument of `LoadTrustStore` is the state of the
list in use, and `nil` accepts any correctly signed list, even an older one: keep `VerifiedTSL.State`, across restarts too, and pass it to
the next load.

The checks always run in this order:

1. **Chain and path:** the chain is built and checked against RFC 5280, with the end entity's requirements.
2. **Type:** the type must be one the profile accepts, as the certificate shows it.
3. **Key:** the end entity's key must be admissible under gemSpec_Krypt.
4. **Listed CAs:** every CA must be named by the verified TSL.
5. **CA types:** the TSL must let the issuing CA issue this type.
6. **Revoked CAs:** a CA the TSL revoked vouches only for what it issued before that.
7. **Revocation:** OCSP, only if nothing above has failed.
8. **Roles:** the admission roles, only for a certificate valid otherwise.

Step 7 is late on purpose: a responder's address comes from the certificate, so a forged certificate must
not be able to send a request anywhere.

**The verdict.** Only `result.Valid` decides. It means no error, and a warning never changes it. Every
failure lands in `result.Errors`; `Validate` itself returns an error only when given no certificate, or
when the path check cannot start.

**Findings.** Each finding carries an `ErrorCode`, a constant such as `CodePolicyMismatch` or
`CodeCANotInTSL`. Match on the code, not on the message. `ErrorCodes` lists them all, and `spec/pki-profiles`
holds them to the same values as `ti-pki`.

**Revocation modes.** The mode decides what an OCSP outcome means:

| Outcome | hard-fail | soft-fail |
|---------|-----------|-----------|
| good | passes | passes |
| revoked at or before the time checked | error | error |
| revoked after the time checked | warning | warning |
| unknown, or responder unavailable | error | warning |
| responder untrusted, or response invalid | error | error |

So soft-fail forgives only a responder that cannot answer, never one that cannot be trusted. Every
profile is hard-fail, so a validator built from a profile never forgives either, and an OCSP outage refuses
its certificates. Soft-fail applies only to a `Validator` configured without a profile.

## TLS servers

`ServerCheck` is the `ti` profile of [`spec/pki-validation`](../../spec/pki-validation): what a TLS client
checks of a TI server before it sends anything, independent of the TLS library. The library hands over the
chain, the host name it connected to and the stapled OCSP response:

```go
check := tipki.NewServerCheck(store) // nil while no TSL is within its grace period
verdict := check.Verify(ctx, chain, "svc.example.ti", stapled, now, tipki.NewOCSPChecker(transport))
if !verdict.Valid() {
	return fmt.Errorf("server refused: %s: %s", verdict.Code, verdict.Detail)
}
```

The chain is validated as a C.FD.TLS-S or C.ZD.TLS-S without revocation, then no SHA-1, MD5 or SHA-224
signature may appear below the root, then the host must be the commonName or a `dNSName` (a wildcard
stands for exactly one leftmost label), and last the OCSP status: from the stapled response if it is
within `OCSPGrace` (10 minutes by default), else from the responder. `NotAfter`, `ProducedAt` and
`NextUpdate` bound how long an accepted verdict may be reused.

Package `titls` puts both profiles of the spec into a `crypto/tls` client configuration: `ti` through
`ServerCheck` over a `TrustSource` the host swaps on each TSL reload, and `web` over the system's roots with
the profile's key, name, validity and revocation rules (stapled OCSP, the responder, the CRL). It reuses
accepted verdicts in a bounded cache and reaches responders and CRL hosts only through the host's
`*http.Client`. Its package documentation lists what `crypto/tls` cannot offer as `handshake.json` has it.

Package `fetch` is the host-side piece for a workload with no producer to mount a bundle from: over the
host's `*http.Client` it downloads an environment's roots and TSL from the fixed hosts, takes a list only
under the SHA-256 the HTTPS host names, verifies everything as a bundle, refreshes hourly in the background
and fails closed once the copy is 24 hours past its last good refresh or the list's `NextUpdate` has passed.
Its `Source` is the `titls.TrustSource` it swaps on each change, and withdraws at that moment.

## Security posture

- **Trust comes from verification only.** Trust starts at the pinned anchors, and a TSL counts only
  once its signature has been verified. A chain passing does not by itself mean a certificate is
  accepted.
- **Unknown means refused.** A critical extension that is not processed is an error. Name and policy
  constraints are not implemented, so a CA marking them critical is refused.
- **One identifier has one spelling.** Text such as `1.2.030`, which `x509.ParseOID` reads as `1.2.30`,
  is refused, and identifiers are compared in binary.

This library has **not** undergone an independent third-party audit.

## Validation

- **Conformance to Rust's `ti-pki`.** Both implementations are held to language-neutral rules with
  shared test data: [`spec/pki-profiles`](../../spec/pki-profiles) and
  [`spec/pki-path`](../../spec/pki-path). `ti-pki` writes the corpora and `tipki` must read the same.
  The `ti` cases of [`spec/pki-validation`](../../spec/pki-validation) hold `ServerCheck` to the same
  codes as `ti_pki::tls`.
- **Fuzzing** of the parsers for certificates, admission, bundles, roots, TSL, detached signatures, OCSP
  responses and identifiers.
- **Live tests** run through `go/idpd`, against the TSL and the IDP-Dienst of the reference environment.

## References

- **gemSpec_PKI** V2.28.0, **gemSpec_TSL** V1.25.0, **gemSpec_Krypt** V2.51.0, **gemSpec_OID** V3.26.0,
  **gemKPT_PKI_TIP** V2.14.0 ([gematik](https://gemspec.gematik.de/)).
- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate and CRL Profile.
- **RFC 6960**: Online Certificate Status Protocol (OCSP).

## Package layout

```
tipki/      Certificates, profiles, TSL, chains, OCSP, Validator, ServerCheck
  oid/      The identifiers of gemSpec_OID
  titls/    TLS client configurations for the ti and web profiles of spec/pki-validation
  fetch/    Download and background refresh of an environment's trust material
```

## Development

The [repository's rules](../../docs/README.md) apply, and versions are this module's own tags,
`go/tipki/vX.Y.Z`. The corpora are written by `ti-pki`, with `TI_PKI_BLESS=1`.

```bash
go test ./...
go test -run x -fuzz FuzzParseTSL -fuzztime 30s .
go test -run x -fuzz FuzzWebCheck -fuzztime 30s ./titls
```
