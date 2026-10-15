# Languages

The rules in this directory are language-independent. Each language has a **profile**
next to its code that says how that language meets them, and adds what only that
language needs. A profile maps rules; it does not restate them, and it lists no gaps
(those are backlog tasks with the language's label).

| Language | Role | Profile | Development guide |
|---|---|---|---|
| Rust | the core: PKI, TSL, JOSE, TI protocols, smartcard and Konnektor; CLI; WebAssembly | [rust/docs/design.md](../rust/docs/design.md) | [rust/docs/development.md](../rust/docs/development.md) |
| Go | servers, relying parties and their libraries; ePA client | [go/docs/design.md](../go/docs/design.md) | [go/docs/development.md](../go/docs/development.md) |
| Swift, Kotlin/Java, JavaScript/TypeScript | bindings to the Rust core on client platforms (planned) | to be written before the first code | — |

## What every profile answers

A profile has these sections, in this order, so profiles can be compared side by side
(a section that does not apply says so in one line):

1. **Role and units.** What the language does here; its units (crates, modules,
   packages) per layer of the [architecture](architecture.md#layers).
2. **Sans I/O and transports.** The transport seam (interface and its threading
   assumptions), the clock and randomness seams, where configuration is read.
3. **Keys and cryptography.** The default crypto backend; one table mapping the
   [key rules](design/keys.md) to the language's types: sign, decrypt or key agreement,
   capabilities and attestation, software key, the async and cancellable form.
4. **Errors and result codes.** How the language's errors carry the result codes of the
   shared specifications.
5. **Testing.** Test framework; the syntax for requirement-named tests; the gated-test
   mechanism (skip or ignore, with the variable and recipe); fakes and fixtures.
6. **Verification and tooling.** The tool for each category of
   [verification](design/testing.md#verification-and-tooling) and where it runs today
   (`just check`, `just audit`, design time).
7. **Fuzzing.** Tool, layout, toolchain, and the targets the language's units need.
8. **Dependencies.** The standard library and its extensions, the preferred libraries,
   where a dependency's reason is recorded, the supply-chain checks.
9. **Crossing languages.** How the language uses or offers the core
   ([interop](interop.md)): process boundary, bindings, native implementation under a
   shared spec, and what it must never do (link a native core into a server process).
10. **Servers** (where the language hosts servers): how the
    [server rules](design/servers.md) map to its HTTP stack, storage, sealing, telemetry
    and images.
11. **Build and release.** Pointers into the development guide: build, versions, tags,
    release notes, gated suites per unit.
12. **Status.** The backlog label(s) for the language's gaps and the few tasks that
    matter most right now.

## Adding a language or binding

Before the first line of code in a new language:

- [ ] a profile following the sections above, reviewed like a design change;
- [ ] a development guide: build, test, versions and tags (`<language>/<unit>/vX.Y.Z`),
      release notes, a "Gated tests" table;
- [ ] `just check` in the new workspace covering format, lints, tests, the layer and
      dependency checks of the profile, and the supply-chain checks;
- [ ] gematik OSPO headers on every source file and the licence policy for dependencies;
- [ ] a backlog label for its tasks;
- [ ] for a binding: which engines it exposes, how the host supplies transports, keys and
      clocks, and how the shared spec corpora run through the binding.
