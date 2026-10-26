# zero-lab

This is security-critical software for the German Telematikinfrastruktur: correctness and
security before convenience, features or speed of delivery. The binding rules for every
language are in [`docs/`](docs/README.md); read the documents a change touches before
planning it. This file only summarises them and adds what applies to agents.

## The criteria every change is held against

Full text: [docs/principles.md](docs/principles.md). Check a plan against them before
writing it and the change before calling it done; a change that falls short says so and
why, or does not land.

1. Sans I/O cores ([architecture](docs/architecture.md#sans-io)).
2. Transport independent, trust in the core: the host's TLS uses the core's verifier
   ([architecture](docs/architecture.md#the-host-owns-the-transport-the-core-owns-trust)).
3. Portable, including WebAssembly ([architecture](docs/architecture.md#portability)).
4. Trust from verification only ([architecture](docs/architecture.md#trust-from-verification-only)).
5. Pluggable crypto; private keys as functions; hardware-bound keys
   ([keys](docs/design/keys.md)).
6. Testable logic; tests named after the requirement they prove; gated tests run before
   releases ([testing](docs/design/testing.md)).
7. Verified, not only tested ([testing](docs/design/testing.md#verification-and-tooling)).
8. Few, stable, maintained, evaluated dependencies
   ([dependencies](docs/conventions/dependencies.md)).
9. Fuzzed ([testing](docs/design/testing.md#fuzzing)).
10. Servers are confidential workloads, 26 rules ([servers](docs/design/servers.md)).
11. Languages meet through processes or shared specifications ([interop](docs/interop.md)).

Conventions: [naming and configuration](docs/conventions/naming-and-config.md),
[code and comments](docs/conventions/code-and-comments.md),
[git and releases](docs/conventions/git-and-releases.md),
[backlog](docs/conventions/backlog.md), [text for agents](docs/conventions/agents.md).
Language profiles: [Rust](rust/docs/design.md), [Go](go/docs/design.md); development
guides next to them.

## For agents

- **Dependencies:** ask the maintainer before adding a dependency, enabling a feature that
  pulls new ones, or swapping a library, with the reason, the transitive cost and the
  alternatives.
- **Checks:** run `just check` in each workspace you changed (`rust/`, `go/`). Never weaken
  a lint, a check or a proof to get a change through. Regenerate stale generated files
  instead of editing them: `just jwz-recheck` for verification stamps,
  `JWZ_BLESS=1 cargo test -p jwz --test traceability` for jwz's traceability table.
- **Tests:** name each test of a rule after the requirement it proves; a new parser comes
  with its fuzz target; a gated test never passes silently.
- **OpenAPI contracts:** load the `gematik-openapi-lint` skill if it is installed before
  writing or changing one, run `just api-lint` in `go/`, never reconstruct rules from
  memory, and never copy the internal ruleset into this repository.
- **Backlog** ([rules](docs/conventions/backlog.md)): work starts from a task. Before
  starting, find it (`backlog task list --plain`, `backlog search …`, from the repository root) or
  create it; set it `In Progress`, keep the plan and notes in it while working, tick each
  acceptance criterion when met, and set it `Done` with a final summary in the pull
  request that completes it. A gap against the rules or a finding outside the current
  change becomes its own task, not a list in a document or a wider change. Use the CLI
  rather than editing task files by hand.
- **Documents:** each rule lives in one document under `docs/`; change that document, not
  this file. Profiles map rules to their language and do not restate them. Keep this file
  a summary with links.
- **Sources:** every new source file starts with the EUPL header its neighbours use.
