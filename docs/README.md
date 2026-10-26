# zero-lab documentation

zero-lab builds trust decisions for the German Telematikinfrastruktur (TI). The documents
here are the binding rules for all of it, in every language; each language workspace adds
a profile that says how its code meets them.

## Reading order

1. [Principles](principles.md): why this is security-critical and the criteria every change
   is held against.
2. [Architecture](architecture.md): which language does what, the layers, sans I/O,
   transport independence, trust from verification, offline operation, portability.
3. The design rules, one topic each:
   - [Keys and cryptography](design/keys.md): pluggable crypto, private keys as functions,
     hardware-bound keys.
   - [Servers](design/servers.md): server software as confidential workloads.
   - [Testing and verification](design/testing.md): testable logic, requirement-named tests,
     gated tests, fuzzing, formal verification.
4. [Crossing languages](interop.md): process boundaries, RPC, shared specifications,
   bindings.
5. Conventions:
   - [Dependencies](conventions/dependencies.md)
   - [Naming and configuration](conventions/naming-and-config.md)
   - [Code and comments](conventions/code-and-comments.md)
   - [Git and releases](conventions/git-and-releases.md)
   - [Backlog](conventions/backlog.md)
6. [Languages](languages.md): the profile every language follows, and the profiles:
   [Rust](../rust/docs/design.md), [Go](../go/docs/design.md).

## Where else

| What | Where |
|---|---|
| Shared specifications (rules, result codes, corpora) | [`spec/`](../spec/README.md) |
| Development and release guides per workspace | [`rust/docs/development.md`](../rust/docs/development.md), [`go/docs/development.md`](../go/docs/development.md) |
| Decisions and the architecture decision record | [`backlog/decisions/`](../backlog/decisions/), [doc-1](../backlog/docs/doc-1%20-%20Rust-as-the-core-architecture-Go-review-integration-means-workflow.md) |
| Open work, including every gap against these rules | the backlog in [`backlog/`](../backlog/); [how it is used](conventions/backlog.md) |
| Contributing | [`CONTRIBUTING.md`](../CONTRIBUTING.md) |

## Owning a rule

Each rule lives in exactly one document above; others link to it. Changing a rule means
changing that document. Language profiles map rules to their language and add what only
their language needs; they do not restate the rules. Gaps are backlog tasks, not lists in
these documents.
