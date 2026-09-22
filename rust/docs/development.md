# Development & Release Guide

This guide covers day-to-day local development against the Cargo workspace and how to cut
tagged, reproducible releases. All commands are run from the `rust/` directory, where the
workspace `Cargo.toml` and the `Justfile` live. It mirrors the Go side
([`go/docs/development.md`](../../go/docs/development.md)); the differences are called out
where they matter.

## Versioning model in one minute

**Every crate is versioned solely by its own git tag** `rust/<crate>/vX.Y.Z`, bumped only
when that crate changes. There is no shared version: the workspace deliberately has no
`workspace.package.version`, an unchanged crate keeps its tag, and the number just reflects
that crate's own history. The `version` in each crate's `Cargo.toml` always equals its
latest tag (or the upcoming one, on the release commit).

- **Local development** uses the workspace `Cargo.toml`, which plays the role of `go.work`:
  every in-repo crate resolves from local source through the `path` in
  `[workspace.dependencies]`, so a library edit is used immediately by every crate that
  depends on it. Unlike `go.work` there is nothing to opt out of — Cargo always builds a
  workspace member from its path.
- **Sibling crates are resolved by `version`, not by git tag.** Each in-repo entry in
  `[workspace.dependencies]` carries both a `path` and a `version`
  (`ti-pki = { version = "0.1", path = "ti-pki" }`). The path is used locally; the version is
  what a packaged or published crate records for its dependency. A library bump therefore
  has to update that line together with the crate version and changelog. This replaces
  `just sync` from the Go side.
- **Rust code always uses the snake_case form** of a crate name: the package is `ti-pki`,
  the import is `use ti_pki::...;`.

Inspect and manage versions:

```console
just versions          # latest tag per crate
just changed           # crates with commits since their last tag (candidates to bump)
just tag <crate> <ver> # e.g. just tag ti-pki 0.1.0  -> tags rust/ti-pki/v0.1.0
```

## Part A — Local development (workspace)

```console
git clone https://github.com/gematik/zero-lab.git
cd zero-lab/rust                     # the workspace Cargo.toml lives here
just tools                           # once: the pinned cargo tools

# Edit a crate
$EDITOR ti-pki/src/chain.rs

# Build / test — the change is already in effect for every workspace member
cargo build --workspace
cargo test -p ti-pki
```

Confirm the workspace is wiring local source:

```console
cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "ti-pki") | .manifest_path'
# => …/zero-lab/rust/ti-pki/Cargo.toml   (a local path = the workspace resolving it locally)
```

Checks come in two tiers:

```console
just check    # tier 1, every PR: fmt, clippy, doc, test, features, machete, deny
just audit    # tier 2, before tagging: advisories, vet, msrv, semver
```

External dependencies are pinned once in `[workspace.dependencies]` and inherited with
`<dep>.workspace = true`. `Cargo.lock` is committed. Adding or updating a dependency makes
`just vet` fail until the new version is audited (`cargo vet certify`) or covered by an
imported audit; `just vet-suggest` lists what is outstanding.

## Part B — Tag & reproducible builds

A crate consumed by git tag or from a registry is built **outside** this workspace, so its
in-repo dependencies resolve by the `version` recorded in its `Cargo.toml`, not by path. To
make a release pick up a sibling's change, that sibling must be released first and the
dependent's version requirement raised.

```console
# 1. Land the change on main (PR, review, merge)

# 2. Bump the changed crates: `version` in <crate>/Cargo.toml, its line in
#    [workspace.dependencies] when siblings need the new version, and CHANGELOG.md
just changed                       # what changed since each crate's last tag
git add -A && git commit -m "ti-pki: release 0.1.1"

# 3. Tier 2 must be green before tagging (semver compares against the last tag)
just audit

# 4. Tag the crates that changed, then push the tags
just tag ti-pki 0.1.1
just push-tags
```

Only tag what actually changed — `just changed` lists crates with commits since their last
tag. Unchanged crates keep their existing tag. Check what a release would contain with
`just package-list <crate>`: only the crate's `Cargo.toml`, `README.md`, `CHANGELOG.md`, `LICENSE` and
`src/` may appear.

### Reproducible library consumption from another project

Consumption goes through three stages as the distribution matures:

```toml
# 1. git, pinned to the crate's own tag (Cargo finds the crate by name in the workspace)
ti-pki = { git = "https://github.com/gematik/zero-lab", tag = "rust/ti-pki/v0.1.0" }
# 2. internal registry (once configured)
ti-pki = { version = "0.1", registry = "gematik" }
# 3. crates.io
ti-pki = "0.1"
```

A git dependency is exact: the tag names one commit, and the consumer's `Cargo.lock`
records its hash. Crates are `publish = false` until the registry decision is made.

### release-plz

`release-plz.toml` is prepared (tag format `rust/<crate>/v<ver>`, changelog updates) but
not yet usable: release-plz derives the next version from the registry, which it skips for
`publish = false` crates, and its `git_only` mode (as of 0.3.169) fails for a workspace that
is not at the repository root. Until a registry is in place, bumps are done by hand as
above; afterwards `release-plz update` does the version, sibling-pin and changelog edits.

## The golden rule

- **Develop** against the workspace — local, fast, no tags, no version edits.
- **Release** = land the change → bump version, sibling pin and changelog → `just audit` →
  `just tag <crate> <version>` for each changed crate → `just push-tags`. Only then do git-tag
  consumers see the new code, because those builds bypass the workspace paths.

## `just` recipe reference

| Recipe | Purpose |
| --- | --- |
| `tools` | Install the pinned cargo tools (via cargo-binstall when available) |
| `check` | Tier 1: `fmt`, `clippy`, `doc`, `test`, `features`, `machete`, `deny` |
| `audit` | Tier 2: `advisories`, `vet`, `msrv`, `semver` |
| `vet-suggest` | Dependencies still awaiting a cargo vet audit |
| `miri`, `mutants <crate>` | On demand: Miri (nightly), mutation testing |
| `versions` | Show the latest tag for every crate |
| `changed` | List crates with commits since their last tag |
| `tag <crate> <ver>` | Create the `rust/<crate>/v<ver>` release tag |
| `push-tags` | Push all local tags to origin |
| `package-list <crate>` | Show the files a release of the crate would contain |
