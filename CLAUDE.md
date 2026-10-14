# zero-lab

## This is security-critical software

zero-lab builds trust decisions for the German Telematikinfrastruktur: PKI path
validation, TSL verification, OCSP, JOSE, IDP authentication, smartcard and Konnektor
access, ePA VAU. A defect here can accept a forged certificate, leak key material or let
an attacker in. Treat every change accordingly: correctness and security before
convenience, features or speed of delivery.

## Every change is held against these criteria

The design in `rust/docs/design.md` is binding for all future development, in Rust and,
where it applies, in Go. Check a plan before writing it and the change before calling it
done; a change that falls short of one says so and why, or does not land.

1. **Sans I/O:** cores do no network, file or clock access of their own.
2. **Transport independent:** HTTP comes from the host through a small trait; no client
   in a core.
3. **Portable:** cores build for `wasm32-unknown-unknown`; `no_std` + `alloc` where the
   crates below allow it.
4. **Trust from verification only:** where bytes came from never makes them trusted;
   signatures and the anchor decide.
5. **Pluggable crypto, private keys as functions** (below).
6. **Testable logic** (below).
7. **Verified, not only tested** (below).
8. **Few, stable, maintained, evaluated dependencies** (below).
9. **Fuzzed:** every reader of attacker-chosen bytes has a fuzz target.

Gaps the code still has against these are listed in `rust/docs/design.md`; work on a
crate closes its gaps rather than adding to them, and a new gap is recorded there.

## Cryptography is pluggable; private keys are functions, not values

Protocol code reaches cryptography only through traits a backend implements, never by
calling a crypto library directly. An API that needs a private key takes something it can
ask to sign, decrypt or agree on a key (`Signer`, `AsyncSigner`, `KeyAgreement`, Go's
`crypto.Signer` / `crypto.Decrypter`), never the key's bytes, so the key can live in an
HSM, a smartcard behind a Konnektor, WebCrypto or a cloud KMS. Provide the async form
wherever such a key may be used. Key bytes exist only in software key implementations
and the file formats that carry them, zeroized. Design: `rust/docs/design.md`.

## Testable logic, verified code

Keep decisions pure functions of bytes, time and configuration; I/O, clocks, keys and
crypto come in through traits, so every rule is tested without a network, card or clock.
A change to security logic comes with tests that name the rule (`spec/` IDs) and assert
why an input is rejected, not only that it is. Use the Rust tools as part of the work,
not afterwards: a fuzz target for every parser of untrusted input (a new parser comes
with its target; a crash becomes a regression test before the fix), property tests for
invariants, Kani for length and offset arithmetic, formal proof (Kani, hax/F*) for
cryptographic code we write ourselves, limits on attacker-controlled sizes and costs
before any work. Never weaken a lint, a check or a proof to get a change through; a stale
stamp is rerun (`just jwz-recheck`), not edited. Inventory and gaps:
`rust/docs/design.md`, "Making the sources safe and secure".

## Dependencies: as few as possible, only stable, evaluated, secure

Every dependency is code we ship and vouch for without having written it. The default
answer to a new dependency is no.

1. **Standard library first.** Go: stdlib, then `golang.org/x`. Rust: `core`/`alloc`/`std`.
   A few dozen lines of our own, tested, beat a crate or module for anything that is not
   cryptography or a parser of hostile input with a serious implementation available.
2. **Reuse before adding.** If a dependency already in the tree does the job, use it
   rather than a second library for the same purpose (two base64s, two XML parsers, two
   JOSE libraries).
3. **Only stable, evaluated, maintained libraries.** Preferred: Go stdlib and `x/`,
   RustCrypto, rustls and ring, dalek, serde. A candidate must be widely used, actively
   maintained by more than one person, have a security history we can read (advisories,
   audits, fuzzing), and a released, non-pre-release version. A pre-release or otherwise
   immature dependency is allowed only when nothing stable exists, and is then listed
   under "Known compromises" in `rust/docs/development.md` with the trigger that removes it.
4. **Never hand-roll cryptography for operations on secrets.** Signature verification
   and other operations on public data use the standard implementation (Go stdlib,
   RustCrypto). Custom constant-time code exists only where no evaluated implementation
   does, and is then formally verified (Kani, hax) like jwz's.
5. **Minimal surface.** `default-features = false` and only the features used. Weigh the
   transitive tree, not only the direct crate: `cargo tree -i <crate>`, `go mod graph`.
   Runtime glue (HTTP clients, executors, platform APIs) stays behind opt-in features or
   in adapter crates, never in a core crate.
6. **Latest versions.** Keep the latest Go and the latest release of every dependency;
   never downgrade for compatibility. A fixed advisory is a release blocker.
7. **Ask first.** Adding a dependency, enabling a feature that pulls new crates or
   modules, or swapping one library for another needs the maintainer's approval, with the
   reason, the transitive cost, and the alternatives considered. Record the reason next to
   the dependency (a comment in `Cargo.toml` `[workspace.dependencies]`, or `go.mod`
   context in the module's docs).
8. **Removal is a feature.** When a dependency's use shrinks to something small, replace
   it and delete it.

Checks that must stay green: `just check` in `rust/` (includes `cargo deny`: licences,
advisories, bans, sources) and `just audit` before tagging (`cargo audit`, `cargo vet`,
MSRV, semver); `govulncheck ./...` in every Go module you touch.

## Layout

- `go/`: Go modules, one tag each (`go/<module>/vX.Y.Z`); guide in `go/docs/development.md`.
- `rust/`: Rust workspace, one tag per crate (`rust/<crate>/vX.Y.Z`); guide in
  `rust/docs/development.md`, design in `rust/docs/design.md`.
- `spec/`: normative rule sets with corpora and conformance tables shared by both.

All code is EUPL-1.2; every source file starts with the header the existing files use.
