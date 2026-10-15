# Testing and verification

## Testable logic

Sans I/O is what makes the logic testable, and the tests are designed in, not added:

- **Decisions are pure.** Validation, policy, protocol steps and parsers take bytes, a
  time and a configuration and return a result; nothing reads the clock, the network or
  the environment on the way. A test states its inputs completely, and every rule is
  tested without a network, card or clock.
- **Seams are interfaces.** Transports, clocks, cache stores, crypto backends and keys are
  interfaces, so tests substitute scripted transports, fixed clocks, in-memory stores and
  mock HSM signers instead of patching globals. Fakes over mocks: small hand-written
  implementations of the consumer's interface.
- **Results explain themselves.** Outcomes carry the reason (error codes, warnings,
  reload outcomes), so a test asserts *why* something was rejected, not only that it was.
- **Specs drive tests.** Rules carry IDs in `spec/<topic>` with a corpus and a
  `CONFORMANCE.md`; fixtures are canonical in `spec/`, copies are hash-pinned, and every
  implementation runs the same corpus ([interop](../interop.md)).
- **Test vectors from outside.** Wycheproof for every primitive, the W3C C14N suites,
  gematik's reference data (ref-GemLibPki), and interop fixtures cross-checked against
  independent implementations (Go, Rust, Python, OpenSSL, the JDK).
- **Same tests everywhere.** Native, in WebAssembly in a real browser, and live tests
  against the TI test environments kept apart from the offline suite (gated, below).

## Tests name the requirement they prove

Every test of a rule says which rule, so that a requirement can be traced to the code
that implements it and the tests that prove it, and a requirement without a test shows.

- **In the name.** The test is named after the requirement, normalised to an identifier,
  then what it shows: `p12_036_mac_iterations_above_the_limit_are_refused`,
  `tslsig_066_…`, `a_28419_…` (gematik afo), `tuc_pki_002_…`, `rfc_7516_5_2_…`. Each
  language profile gives the exact syntax. Several requirements: the most specific one in
  the name, the others in the doc comment.
- **In the source.** The code that implements a requirement cites it in a comment
  (`P12-036: …`, `RFC 7516 §5.2: …`, `gemSpec_PKI A_28419: …`), in the form the
  traceability tables parse.
- **Kinds of reference**, most specific first: a rule of our own spec (`spec/<topic>`,
  `TOPIC-nnn`), a gematik requirement (afo `A_nnnnn`, `TUC_…`, `GS-A_…`, with the document
  and version it is from), an RFC or standard section, an ADR or design rule of this
  repository. A test of an internal invariant with no external requirement says so in its
  doc comment.
- **Traced, not only named.** Where a unit has a traceability table (jwz's
  `docs/traceability.md`, generated and checked by a test), new references and tests
  appear there; a spec's `CONFORMANCE.md` maps its rules to corpus cases. A requirement
  that is implemented but has no test is a gap, a backlog task until it has one.

## Env-gated tests run before every release

Tests that need something outside the repository (the TI test environments, a Konnektor,
a smartcard, the IDP-Dienst, a database, a real browser, a human) are gated, never
deleted, never faked away, and never skipped silently.

- **One gate, named for what it needs.** An environment variable per resource, prefixed
  by the component (`TI_TEST_KON_PATH`, `ZERO_PDP_E2E_URL`, `GEMIDP_SMCB_P12_PATH`);
  [naming](../conventions/naming-and-config.md) applies: paths end in `_PATH` or `_DIR`,
  secrets come from files, never from the variable's value. Test material is TEST-ONLY.
- **Loud when skipped.** A gated test shows as skipped or ignored with the variable it
  needs and what it would prove, never as passed; run explicitly without its
  configuration, it fails with the variable it needs. The profiles give the mechanism.
- **One recipe per suite.** Each gated suite has a `just` recipe that checks its
  variables, says what is missing and runs it (`just real-world`, `just pdp-e2e`,
  `just epa-connect-test`, …). Human-in-the-loop suites are marked HITL and need a person.
- **Documented in one table** per workspace (the development guide's "Gated tests"):
  suite, recipe, variables, prerequisites, what it proves, and the units whose release
  requires it.
- **Required before a release.** `just check` and CI never run them, so a green CI says
  nothing about these paths. Before tagging a unit, every gated suite listed for it runs
  green against the real system, and the release PR records which suites ran, against
  what, on which commit. A suite that cannot run blocks the release or is waived
  explicitly, with the reason, in the release PR; never silently
  ([releases](../conventions/git-and-releases.md)).

## Verification and tooling

The language's memory-safety guarantees are the starting point; the tools go after the
rest: logic errors, panics on hostile input, timing, resource exhaustion and the supply
chain. Each runs in `just check` (every change), `just audit` (before a tag) or at design
time with a stamped result that `just check` holds to. Never weaken a lint, a check or a
proof to get a change through; a stale stamp is rerun, not edited.

| Category | What it shows | When |
|---|---|---|
| unsafe-code ban, strict lints, documented API | no memory-unsafe code of our own, lint-clean, every public item documented | check |
| build matrix and layer checks | every feature or tag combination builds; cores stay I/O-free; no TEST-ONLY bytes in production builds | check |
| bounded model checking | no panics, overflows or out-of-bounds, and stated properties | design time, stamped |
| functional proof against the spec | correctness of cryptographic constructions we implement | design time, stamped |
| fuzzing | no panic, hang or broken invariant on any input | release, design time |
| property tests | invariants over generated inputs | check |
| known-answer, spec corpora, interop | known-answer and edge cases, same verdicts as other implementations | check |
| race detection, sanitizers | no data races or undefined behaviour where the language allows them | check |
| mutation testing | the tests notice when the code changes | before a release |
| supply chain | licences, bans, sources, advisories, audited dependencies | check / audit |
| compatibility | no accidental API breaks, declared toolchain, no unused dependencies | audit / check |

The language profiles name the tool for each category and where it runs today.

Required of every unit that parses untrusted input or holds a security decision:

- a fuzz target for each parser of untrusted input;
- property tests for invariants (round trips, canonical forms, monotone policies);
- model checking for code with arithmetic on lengths and offsets, and formal proof for
  cryptographic constructions we implement ourselves;
- resource limits on attacker-controlled parameters (sizes, depths, iteration counts,
  KDF cost) checked before any work is done;
- secret material in zeroizing buffers, constant-time comparison of digests and MACs,
  private keys used by function only ([keys](keys.md));
- hostile input parsed strictly: DER through a strict DER parser, XML without DTDs, JSON
  with unknown fields rejected where the format is ours.

A language without maintained formal tools keeps security-critical algorithms out of
hand-written code instead (standard library, generated and verified code, or the Rust
core), and covers the rest with fuzzing, race detection and the shared spec corpora.

## Fuzzing

Every parser of untrusted input and every function that makes a decision on it is fuzzed.

- **One target per entry point**, documented with what it asserts. A target asserts more
  than "no panic": what parses survives its own serialization, a canonical form is a
  fixed point, a verdict is the same through every API that reaches it, limits hold.
- **Seeds are committed**, drawn from the spec corpora, Wycheproof and real TI artefacts
  (TSL, roots.json, OCSP responses, certificates); a growing corpus is not, except
  crashers.
- **A recipe per unit** (`just fuzz-<unit> seconds`) runs every target and fails on a
  crash; a short run is part of a release, long runs happen at design time and after
  changes to a parser.
- **A crash becomes a regression test before it is fixed**: minimised, added with the
  input in the unit's test data, then fixed.
- **Structure-aware targets** where random bytes rarely get past the outer format, such
  as DER inside base64 inside JSON, or XML around a signature.
- **A new parser comes with its target.**

Each profile lists the targets its units need.
