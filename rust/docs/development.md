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
  has to update that line together with the crate version and release notes. This replaces
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
just check    # tier 1: fmt, clippy, doc, test, features, wasm32, core-deps, nonprod-absent, machete, deny
just audit    # tier 2, before tagging: advisories, vet, msrv, semver
```

Shared metadata (edition, rust-version, license, repository, authors, publish) lives in
`[workspace.package]` and lints in `[workspace.lints]`; a crate's `Cargo.toml` only states
its name, version, description, keywords and categories, and inherits the rest with
`<field>.workspace = true`. External dependencies are pinned once in
`[workspace.dependencies]` and inherited the same way. `Cargo.lock` is committed. Adding or updating a dependency makes
`just vet` fail until the new version is audited (`cargo vet certify`) or covered by an
imported audit; `just vet-suggest` lists what is outstanding.

## Shared types

Vocabulary every `ti-*` crate must agree on — today the environment (`Env`) and its
production split (`Tier`) — lives in `ti-types`. Its admission rule:

> If it compiles in `no_std` and has no I/O, it may go into `ti-types`; otherwise it doesn't.

No HTTP, no crypto, no async, no product constants (URLs, anchors), no helper functions;
the default build has no dependencies.

`ti-types` goes to 1.0 soon and is additive only from then on. Every enum is
`#[non_exhaustive]`, except `Tier`, whose split is binary by definition. A breaking
redesign gets a new type instead of a major bump: a major bump would split consumers into
incompatible `Env` types that no longer interoperate.

## Environments

Environments are data, not behaviour. Library code never branches on `Env`; everything
that differs between environments — anchor, roots.json, TSL location, the policy
relaxations — is a named field of `ti_pki::TrustConfig`, and `Env` only picks a preset.
The one decision code may make is the `Tier`, and it is made in one place:
`TrustConfig::validate(tier)` rejects TEST-ONLY anchors and every relaxation under
`Tier::Prod`.

The non-production presets and their TEST-ONLY anchors and roots are compiled in only
with the `dangerous-nonprod` feature. A production binary is built without it, and
`just nonprod-absent` proves the compiled crate then contains none of those bytes.

Operators override fields on a preset rather than adding environments — a TSL mirror, a
tighter clock skew, an anchor delivered out of band:

```rust
let config = TrustConfig { tsl_url: mirror.into(), ..TrustConfig::preset_prod() };
config.validate(Tier::Prod)?;
```

Tests in downstream crates use `TrustConfig::for_lab_ca` from the `test-util` feature.

## Signature algorithms

Every signature `ti-pki` checks goes through one trait,
`rustls_pki_types::SignatureVerificationAlgorithm`, the one rustls and webpki use. A
verifier is picked by the exact pair of key algorithm and signature algorithm;
validation code never names a curve. `TrustConfig::algorithms` holds the set.

| Set | Contents | Backend |
| --- | --- | --- |
| `algorithms::STANDARD` | ECDSA P-256/SHA-256, P-384/SHA-384 | RustCrypto `p256`, `p384` |
| `algorithms::brainpool::ALL` (feature `brainpool`, default) | ECDSA brainpoolP256r1/SHA-256, brainpoolP384r1/SHA-384 | RustCrypto `bp256`, `bp384` |
| `algorithms::rsa::ALL` (feature `rsa`, default) | RSA PKCS#1 v1.5 and PSS with SHA-256/384/512 | RustCrypto `rsa` |
| `algorithms::DEFAULT` | `STANDARD` plus brainpool and RSA when enabled; what the presets use | — |

Brainpool is isolated: its own module behind its own feature, referenced only by
`DEFAULT`, and `just core-deps` proves the crate without it contains no brainpool
arithmetic. The TI's anchors are brainpool keys, so the feature is on by default; without
it, `validate` refuses a brainpool anchor instead of failing later. Other
implementations — webpki's FIPS-validated aws-lc-rs set, ML-DSA once post-quantum
certificates appear — plug into the same set without touching the core.

`bp256`/`bp384` gained curve arithmetic only in 0.14 (September 2026) and are not
audited. Verification handles public data, so timing is irrelevant; correctness is
covered by the Wycheproof vectors (`ti-pki/tests/wycheproof/`, excluded from the package)
and by the real TI roots in the unit tests.

RSA is needed even for an ECC-only deployment: the historical roots GEM.RCA2/6/9 are RSA
keys, and the A_28419 walk passes through them to reach GEM.RCA3–5 and GEM.RCA10–11.
Without the `rsa` feature the walk stops at the first RSA root. With it, `ti-pki` builds
the same ten-root store as `gempki` from the same roots.json.

## Known compromises

Accepted trade-offs of a long-lived project whose dependencies are still maturing. Each
names the trigger for removing it.

| Compromise | Why | Remove when |
| --- | --- | --- |
| `rsa = "=0.10.0-rc.18"`, a release candidate | the only `rsa` line on the current RustCrypto stack (`crypto-bigint` 0.7, `sha2` 0.11); 0.9 would pull in a second, older stack | `rsa` 0.10 is released: switch to `"0.10"` |
| ti releases carry unsigned `SHA256SUMS` | signing was deferred; the checksums catch broken downloads and Homebrew pins them in the formula, but a replaced release could replace them too | a release key exists: sign `SHA256SUMS` in `just release` and verify it in `publish-brew` |
| RUSTSEC-2023-0071 ignored (`deny.toml`, `.cargo/audit.toml`) | the Marvin attack targets RSA private-key operations; `ti-pki` only verifies, on public data | a patched `rsa` is released |
| The TSL signer CA does not change at run time: `spec/tsl-xmldsig` part E (TSLSIG-061 – 068: an anchor announced in the TSL becoming active at its `StatusStartingTime`, and the fallback through roots.json) is not implemented. `TrustConfig::tsl_signer_anchors` is a list; a `TSLServiceCertChange` the TSL announces is reported as the warning `tsl_anchor_announced` (logged by the tokio driver, shown by ti), and a release adds the CA to `anchors::TSL_SIGNER_CAS_*` | gematik changes the TSL signer CA rarely (GEM.TSL-CA3 runs until 2028-05-25) and announces it weeks ahead; adding it to the list in a release is simple and auditable, while part E needs persisted announcements re-verified on load, a roots.json path with its own profile, age and OCSP checks, and signed test TSLs | an installation must follow an anchor change without a release |
| The TSL's per-CA metadata is unused: allowed certificate types (SE_1061) | the TSL is verified (`spec/tsl-xmldsig`), but a CA from it is kept only if a root from the A_28419 walk signed it, and nothing else in it decides trust. A certificate's type is checked by its own policies; a CA's standing by OCSP at its root; for OCSP responders see the next row | the TSL becomes a trust source (e.g. for its per-CA type lists) |
| OCSP responders beyond RFC 6960 must be certified by a CA of the issuing CA's TSP that a root signed, not only listed in the TSL: id-kp-OCSPSigning, valid now, signature verified under that TSL CA. Listed by the verified TSL under that TSP they are authorized (`tsl_listed`); not listed, they are accepted with an `ocsp_responder_not_rfc6960` warning | the TSL ties a responder to CAs only by the TSP it is listed under (its supply point and extension are placeholders), and TI TSPs sign for their CAs with delegates of other CAs (ehca: a GEM.KOMP-CA51 delegate answers for GEM.SMCB-CA51 and GEM.SMCB-CA9). Requiring the certification by a CA of the same TSP keeps a listed responder from answering for another TSP's CAs. The D-Trust responders under GEM.OCSP-CA1/3 stay rejected (their CA is not in the TSL) | gematik aligns responder issuance with RFC 6960 (then the fallback without listing goes) |
| OCSP CertIDs use SHA-1 (`sha1` crate) | TI responders reject SHA-256 CertIDs as malformed (RFC 5019 profile). SHA-1 only names the certificate there; integrity rests on the response signature and the SHA-256 certHash | TI responders accept SHA-256 CertIDs |
| `minicbor` licence BlueOak-1.0.0 allowed for that crate only | permissive, OSI-approved; the lightest CBOR codec for the offline bundle | never, unless the licence policy changes |
| `ureq`'s `unversioned` transport API in `ti_connector_client::ureq`, `ureq` pinned `~3.4` | `TlsConfig` takes no certificate verifier, and a Konnektor needs Go's: `.kon` pins accepted by equality, CA chains checked for `expectedHost`, which is also the SNI. A 60-line connector in ureq's chain does the TLS with our rustls config | ureq accepts a custom verifier or rustls config, or the adapter moves to a crate of its own before ti-connector-client 1.0 |
| `webpki-root-certs` licence CDLA-Permissive-2.0 allowed for that crate only | a permissive data licence for Mozilla's root certificates, which `rustls-platform-verifier` bundles for platforms without a usable OS store; only `ti-cli` depends on it | never, unless the licence policy changes |

## Test PKI

Tests validate certificates generated by OpenSSL, not by `ti-pki`: an independent
implementation produces the bytes, so the encoder and the validator cannot share a
mistake. `ti-pki/tests/pki/generate.sh` (run with `just test-pki`) writes the topology of
`gempki`'s `internal/testca` plus a few edge cases (a P-521 key, an RSA-PSS chain, a
looping and a misnamed cross certificate) as PEM files, with validity fixed around
2026-01-01 so they never go stale. Keys exist only while the script runs. The real TI
certificates in `ti-pki/tests/fixtures/` and the Wycheproof vectors complement them.

## The TSL

`ti_pki::tsl` reads gematik's ETSI TS 119 612 list with quick-xml and serde, matching
element names without their namespace prefix. It is used as a directory of candidate
intermediates, not as a trust source: `match_to_roots` keeps a CA only if a root of the
trust store issued and signed it, and the loading layer stores exactly those
(`TrustStore::intermediates`). What the list also says, and why it is not relied on, is in
Known compromises. The production list of September 2026 lists 90 CAs, of which 84 are
kept; the six others are self-signed legacy eGK CAs and two expired SMC-B CAs under the
retired GEM.RCA1. The `tsl` example prints this for any environment, and `chain --tsl`
builds chains from it.

## OCSP

`ti_pki::ocsp` builds requests and verifies responses in the core; `OcspChecker` (feature
`load`) posts them through the same `Transport` that fetches roots.json and the TSL.
The RFC 6960 structures are the crate's own `der` derives rather than `x509-ocsp`, whose
0.2 release sits on the previous RustCrypto stack: the signature must be checked over
the received bytes anyway, and the dozen structures are smaller than the glue between
two `der` versions. A response is accepted only with a matching CertID, an authorized
responder, a certHash over the certificate and within the TUC_PKI_006 window (37.5 s);
`revocation::apply_revocation` holds `gempki`'s table of what each outcome means under
HardFail and SoftFail. The test PKI script produces fixed-time responses (good, revoked,
unknown and the failure cases) signed by OpenSSL, and `tests/fixtures` holds two live
answers of the reference root responder. The `ocsp` example checks every link of a
chain live, the end entity at its CA and each CA at its root.

## Validation and profiles

`Validator` is the entry point: built from a `TrustConfig` and a `TrustStore`, it
validates an end entity through chain building, path validation, the gemSpec_Krypt key
check and OCSP for the end entity and every CA below the root (the TSL is not
authenticated, so a CA's standing comes from OCSP at its root). A profile
(`ti_pki::profile`) fills in a use case's end-entity requirements on top of the type
baseline; automatic selection matches a profile's role before the type's default and
reports ambiguity instead of guessing. A profile's revocation mode can tighten the
configured one but never loosen it, so production stays HardFail even for smb-aut,
whose Go default is SoftFail. `trustdomain` tells production from test certificates
offline, for picking a configuration. The `validate` example strings it all together.

## CLI output: lists are tables

`ti-cli` shows a list of objects as a table: aligned columns under UPPERCASE headings
on a terminal, a Markdown table when piped. A single object is label/value fields in
sections. Every view is written for its command; a generic JSON-to-text renderer was
tried and read worse.

Each table's columns are a decision, not a dump of the JSON:
- the focus column first: what the reader passes to the next command or looks for;
- then the columns that tell rows apart, then one or two details;
- everything else stays in `--format json`;
- nothing that does not decide trust: `pki tsl show` shows only what the CA
  certificates say, never the TSL's own per-CA metadata (provider names, listed types,
  policies).

| Command | Focus | Further columns | Left to JSON |
| --- | --- | --- | --- |
| `pki profiles list` | PROFILE (the `--profile` value) | TYPES, DEFAULT FOR, REVOCATION, ROLES, DESCRIPTION | role OIDs |
| `pki roots list` | ROOT, by generation | ORGANIZATION, KEY, VALIDITY, anchor mark | subject, SHA-256, PEM, walk order |
| `pki tsl show` | CA | ORGANIZATION (subject O=), ROOT (or the reason there is none), VALIDITY | policies, path length, TSL provider, PEM |
| `connector configs` | `*` for the selected one, NAME (the `-c` value) | URL, CONTEXT | path |
| `connector get cards` | HANDLE (what every card command takes) | TYPE, ICCSN, HOLDER | terminal, slot, versions, insert time |
| `connector get certificates` | REF | KEY, SUBJECT, TELEMATIK-ID, VALIDITY, ALGORITHM | profession, dates, PEM |
| `connector get services` | SERVICE | VERSION, used mark, ENDPOINT | product |
| `connector get identities` | TELEMATIK-ID | TYPE, HOLDER, ICCSN, HANDLE | |
| `connector get expiration` | VALID UNTIL | SUBJECT, ICCSN, SERIAL, HANDLE | terminal |
| `connector get status`, errors | CONDITION | SEVERITY, TYPE, SINCE | inactive states |
| `probe` | SERVICE, status mark | HOST, TIME, DETAIL (`{kind} …` on success, the cause otherwise) | kind, URL, source, HTTP status |

A new list command adds its row here with its choice.

## Parity and live tests

`tests/openssl_cross.rs` runs `openssl verify` and `openssl ocsp` next to `ti-pki` on the
same bytes and requires the same verdict: the test PKI's happy and failing chains, the
real reference SMC-B chain, every CA of the production TSL fixture, and the OCSP
fixtures. It skips when `openssl` or its brainpool curves are missing. `just real-world`
runs the ignored tests in `tests/real_world.rs` against gematik's endpoints: roots.json
and TSL of every environment through `HttpLoader` and `Reloader`, a reference SMC-B end
to end with OCSP, and a production SubCA at its root responder. The deliberate
differences to gematik's reference implementation are in
[gemlibpki-comparison.md](gemlibpki-comparison.md).

## Trust material loading

roots.json and the TSL are loaded, cached and hot-reloaded by `ti_pki::load` (feature
`load`). Loaders are untrusted: whatever the source — HTTP, a mounted file, an offline
bundle, a cache — roots.json is verified against the embedded anchor before use, and only
the TSL's CAs that a verified root signed are kept. A misbehaving source can therefore only
deny service or serve stale data, and the freshness policy catches staleness. The module
docs carry the composition and the failure table.

Over HTTP the TSL is not downloaded while the SHA-256 published next to it (`.sha2`)
matches the list in hand; a download must match that hash (A_30044 (2) of C_12791). The
hash only saves the download: the list is verified as before, whatever it says.

The core has no HTTP client and no executor. Runtime glue is opt-in: the `reqwest`
feature provides a transport over a caller-provided `reqwest::Client` (native and
wasm32), the `tokio` feature a background driver with SIGHUP and an admin trigger.
`just core-deps` proves the rest of the crate stays free of them, and `just wasm32`
that the loading layer builds for the browser. The adapters are features rather than
separate crates while everything is 0.x; once `ti-pki` aims for 1.0, `reqwest` (itself
0.x) moves to its own crate so its breaking releases stop forcing `ti-pki` majors.

### Reload strategies

- **Periodic with jitter** (default): `ReloadPolicy::interval` plus a per-process random
  share of `jitter`, so a fleet started together does not reload in lockstep.
- **TSL `NextUpdate` deadline**: with `honor_tsl_next_update`, the next reload is due
  `next_update_lead` before the current TSL's `NextUpdate` if that comes first.
- **External trigger**: SIGHUP (`ti_pki::tokio::on_sighup`) or an admin endpoint / exec
  probe calling `AdminTrigger::trigger`, e.g. right after a ConfigMap update.
- **Lazy on use** — rejected: reloading from `snapshot()` would put network I/O,
  verification latency and their failures into the request path, need an executor
  there, and stampede the origin when many requests notice staleness at once.
  `snapshot()` stays a lock-free read and only refuses expired material.

Production caps `hard_expiry` at `MAX_PROD_HARD_EXPIRY` (24 h); `ReloadPolicy::validate`
and `Reloader::new` enforce it.

### Kubernetes

- A ConfigMap volume updates by atomically repointing its `..data` symlink.
  `FileTransport` reads through the configured path on every call, so it follows the
  swap; never cache a canonicalised path or an open file.
- `subPath` mounts never receive updates; mount the whole volume.
- Updates arrive after the kubelet sync period plus its cache TTL (about a minute by
  default), then on the next reload tick — or trigger one.
- Put roots.json and the TSL in one ConfigMap so they change together.
- Poll, don't watch: inotify is unreliable on these mounts because the files themselves
  never change, only the symlink.

### Offline bundle

For air-gapped deployments, export both artefacts with their metadata on a connected
machine (`Bundle::new(&config, label, material).write(path)`, from material any loader
produced), transfer the CBOR file, and serve it with
`StaticLoader::from_bundle(Bundle::read(path)?, &config)?`, alone or as the backup of a
`FallbackLoader`. The bundle is not signed and needs no signature: it is verified on
import like any other source, and its anchor hash rejects a bundle meant for another
environment up front. It carries `fetched_at`, so it ages out by `hard_expiry` like any
material — in production that means a fresh bundle at least daily.

## Part B — Tag & reproducible builds

A crate consumed by git tag or from a registry is built **outside** this workspace, so its
in-repo dependencies resolve by the `version` recorded in its `Cargo.toml`, not by path. To
make a release pick up a sibling's change, that sibling must be released first and the
dependent's version requirement raised.

```console
# 1. Land the change on main (PR, review, merge)

# 2. Bump the changed crates: `version` in <crate>/Cargo.toml, its line in
#    [workspace.dependencies] when siblings need the new version, and in ReleaseNotes.md
#    the crate's block under "Unreleased" becomes "## Release <crate> X.Y.Z, <date>"
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
`just package-list <crate>`: only the crate's `Cargo.toml`, `README.md`, `LICENSE` and
`src/` may appear. The release notes of all crates are one file, `ReleaseNotes.md`.

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
records its hash. `[workspace.package]` sets `publish = false` for every crate until the
registry decision is made; flipping it there opens them all.

### release-plz

`release-plz.toml` is prepared (tag format `rust/<crate>/v<ver>`) but
not yet usable: release-plz derives the next version from the registry, which it skips for
`publish = false` crates, and its `git_only` mode (as of 0.3.169) fails for a workspace that
is not at the repository root. Until a registry is in place, bumps are done by hand as
above; afterwards `release-plz update` does the version and sibling-pin edits (it writes only
`CHANGELOG.md`, so its changelog updates stay off; release notes are `ReleaseNotes.md`).

## Releasing ti

`ti` is the one crate with binaries. Its release takes two commands from `main`:

1. **`just release X.Y.Z`**, local only. It stops unless `main` is clean and equal to
   `origin/main`, the tag is new and above the last `rust/ti-cli/v*`, and
   `ReleaseNotes.md` has a `### ti-cli` block under `## Unreleased`. Then `just check`,
   `just audit`; the version bump in `ti-cli/Cargo.toml` and `Cargo.lock`; the ti-cli
   block becomes `## Release ti-cli X.Y.Z, YYYY-MM-DD`; `just cli-targets` builds the
   three binaries into `target/dist` with their `SHA256SUMS`; commit `ti-cli: release
   X.Y.Z` and tag `rust/ti-cli/vX.Y.Z`. A failure or Ctrl-C after the gate undoes the
   bump.
2. **`just publish X.Y.Z [OWNER]`**: `git push --atomic origin main <tag>`, `gh release
   create` with the binaries, the checksums and that version's notes (plus install and
   verify lines), then `just publish-brew OWNER X.Y.Z`. `OWNER` defaults to `TAP_OWNER`
   in the Justfile (`spilikin`).

To drop a release that is not published yet: `git tag -d rust/ti-cli/vX.Y.Z && git reset
--keep HEAD~1`.

`publish-brew` takes the checksums from the published release, fills
`ti-cli/Formula/ti.rb` with each platform's asset URL and hash, and pushes it to
`OWNER/homebrew-tap`. The formula installs the release binaries; nothing is compiled on
the user's machine. The checksums are not signed yet (see "Known compromises").

## The golden rule

- **Develop** against the workspace — local, fast, no tags, no version edits.
- **Release** = land the change → bump version, sibling pin and release notes → `just audit` →
  `just tag <crate> <version>` for each changed crate → `just push-tags`. Only then do git-tag
  consumers see the new code, because those builds bypass the workspace paths.

## `just` recipe reference

| Recipe | Purpose |
| --- | --- |
| `tools` | Install the pinned cargo tools (via cargo-binstall when available) |
| `install` | Install `ti` into `~/.cargo/bin`, built like a release |
| `install-fast` | Install `ti` from the `local` profile (thin LTO, incremental): a change in ti-cli rebuilds in about 20 s instead of about 45 s |
| `check` | Tier 1: `fmt`, `clippy`, `doc`, `test`, `features`, `wasm32`, `core-deps`, `nonprod-absent`, `machete`, `deny` |
| `wasm32` | `cargo check` of ti-pki's loading layer and reqwest transport for wasm32 |
| `core-deps` | Prove ti-pki's core pulls in no HTTP client, executor or file watcher |
| `test-pki` | Regenerate the OpenSSL test PKI in `ti-pki/tests/pki` |
| `nonprod-absent` | Prove ti-pki without `dangerous-nonprod` contains no non-prod trust material |
| `audit` | Tier 2: `advisories`, `vet`, `msrv`, `semver` |
| `vet-suggest` | Dependencies still awaiting a cargo vet audit |
| `miri`, `mutants <crate>` | On demand: Miri (nightly), mutation testing |
| `versions` | Show the latest tag for every crate |
| `changed` | List crates with commits since their last tag |
| `tag <crate> <ver>` | Create the `rust/<crate>/v<ver>` release tag |
| `push-tags` | Push all local tags to origin |
| `package-list <crate>` | Show the files a release of the crate would contain |
| `release <ver>` | Prepare a ti release locally (see "Releasing ti") |
| `release-notes [<ver> [<crate>]]` | A crate's notes from `ReleaseNotes.md` (default: ti-cli's pending ones) |
| `publish <ver> [<tap owner>]` | Push and publish a prepared ti release |
| `publish-brew <owner> <ver>` | Point the formula in `<owner>/homebrew-tap` at a ti release |
