# Development & Release Guide

This guide covers day-to-day local development against the Go workspace and how to cut
tagged, reproducible builds. All commands are run from the `go/` directory, where the
`go.work` workspace and the `Justfile` live.

## Versioning model in one minute

**Every module — library and command — is versioned solely by its own git tag**
`go/<module>/vX.Y.Z`, bumped only when that module changes. There is no shared version and
no version variables: an unchanged module keeps its tag, and nothing is "ahead of" or
"behind" anything else. The number just reflects that module's own history.

- **Local development** uses the tracked `go.work` workspace: every in-repo module resolves
  from local source, so a library edit is used immediately by every command — no tags, no
  `go.mod` edits.
- **`go install <cmd>@vX.Y.Z`** reports its version automatically — Go embeds the module
  version in the build info, and each command's `ResolveVersion()` reads it (no ldflags
  needed).
- **Local / Docker builds** stamp the version from `git describe` (the `_modver` helper):
  exactly on a tag → `0.20.2`; a few commits past it → `0.20.2-3-gdeadbeef`; never tagged
  → `dev`.
- **`zero-caddy`** combines its version with the upstream Caddy version as SemVer build
  metadata, e.g. `zero-caddy 0.20.2+caddy2.11.4`.

Inspect and manage versions:

```console
just versions     # latest tag per module
just changed      # modules with commits since their last tag (candidates to bump)
just tag <mod> <ver>   # e.g. just tag brainpool 0.3.1  -> tags go/brainpool/v0.3.1
```

## Part A — Local development (workspace)

```console
git clone https://github.com/gematik/zero-lab.git
cd zero-lab/go                       # go.work lives here

# Edit a library (e.g. brainpool, gempki, oauth, …)
$EDITOR brainpool/parser.go

# Build / test / run — the change is already in effect via go.work
go build ./...
(cd brainpool && go test ./...)
go run ./epa/cmd/zero-epa version

# Build a stamped binary locally (version from the module's git tag)
just build-epa       # ./dist/zero-epa
just build           # all three commands into ./dist/
```

Confirm the workspace is wiring local source:

```console
(cd pdp && go list -m -f '{{.Path}} => {{.Dir}}' github.com/gematik/zero-lab/go/brainpool)
# => …/zero-lab/go/brainpool   (a local directory = go.work resolving it locally)
```

## Module status

Rust is the maintained core of zero-lab (`../rust`; `docs/backlog/docs/doc-1` there has
the architecture). Go keeps the servers and relying parties, and the ePA client.

| Status | Modules | Notes |
| --- | --- | --- |
| Active | `pdp`, `pep`, `bff`, `zaddy`, `kv`, `nonce`, `dpop`, `oauth`, `oidf`, `gemidp`, `epa`, `metsubushi` | `gemidp` serves the servers' relying-party role only; `epa` gets its SMC-B identity, the IDP-Dienst flow and the VAU certificate checks from the Rust `ti` (below) |
| Frozen | `brainpool`, `gempki`, `pkcs12` | bugfix and security only; `gempki` and `pkcs12` stay for `gemidp`'s tests and external consumers, their Rust successors are `ti-pki`/`ti-xmldsig` and `ti-pkcs12` |
| Archived | `ti` (`go/ti/v0.23.4`), `kon` (`go/kon/v0.21.4`), `asl` (`go/asl/v0.0.2`), `libzero` (`go/libzero/v0.1.0`) | removed from the workspace; the tag keeps each `go get`-able; the Rust `ti` and `ti-connector-client` replace the first two |

Archiving a module: tag its last version, remove it from `go.work` and this Justfile,
delete the directory (as commit 9b4054a did for `asl` and `libzero`).

### `epa` needs the Rust `ti`

`epa` runs the `ti` tool (`../rust/ti-cli`) as a subprocess for everything that needs
brainpool or the TI's protocols: `ti identity inspect|sign` for the SMC-B identity and
its signatures, `ti idpd authenticate` for the IDP-Dienst, `ti pki verify` and
`ti pki verify-signature` for the VAU's certificates and host keys. The private key never
enters the Go process.

- Install it: `cd ../rust && just install` (into `~/.cargo/bin`), or set `EPA_TI_BIN` to
  the binary. `zero-epa` checks `ti version` at start-up.
- The identity in `zero-epa.yaml`: `authn_p12_path` with `authn_p12_password_path` (a
  file holding the password; default `00`), or `authn_cert_path` + `authn_key_path`, or
  `authn_card` (+ `authn_connector`) for an SMC-B at the Konnektor. `vau_cert_verify:
  warn|enforce|off` (default `warn`) says what a bad verdict on the VAU's certificates
  does.
- The Docker image builds `ti` in a Rust stage; its build context is the repository root
  (`just docker-build-epa`).
- Tests: `go test ./epa/...` needs no `ti` (the unit tests use fakes); the env-guarded
  `just epa-connect-test` and `just epa-entitle-test` need it and skip when it is
  missing.

Keep modules tidy (no version changes):

```console
just tidy            # go mod tidy per module
just upgrade         # ONLY when deliberately bumping external deps to latest
```

## Part B — Tag & reproducible builds

`go install <cmd>@<tag>` and tag-pinned Docker builds run **outside** `go.work`, so a
command resolves its libraries from its `go.mod`. To make a tagged build pick up a library
change, repin with `just sync` before tagging.

```console
# 1. Land the library change (must be fetchable from the remote)
git add -A && git commit -m "brainpool: <change>"
git push origin <branch>

# 2. Repin in-repo requires to the branch tip so out-of-workspace builds pick it up
just sync                         # default REF = current branch; or: just sync REF=<ref>
git add -A && git commit -m "sync: pin in-repo deps to branch tip"
git push

# 3. Tag the modules that changed (check with `just changed`), then push the tags
just tag brainpool 0.3.1          # the changed library
just tag ti 0.20.3                # any command whose release you're cutting
just push-tags
```

Only tag what actually changed — `just changed` lists modules with commits since their last
tag. Unchanged modules keep their existing tag.

### Reproducible install of a command

`go install` ignores `go.work`, resolves the pinned `go.mod`, and reports its version from
the module build info:

```console
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@v0.20.3
zero-epa version  # -> "0.20.3"
```

The `@` takes the bare semver (`v0.20.3`); Go maps the module's `go/epa` subdirectory to the
`go/epa/v0.20.3` tag automatically.

If `proxy.golang.org` returns "unknown revision"/404 right after tagging (it negatively
caches a version that didn't exist yet), fetch directly:

```console
go env -w GOPRIVATE=github.com/gematik/zero-lab   # once; installs bypass the proxy/sumdb
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@v0.20.3
```

### Reproducible library consumption from another project

```console
go get github.com/gematik/zero-lab/go/gempki@v0.20.2   # the library's own tag
```

### Reproducible Docker images

The build context includes `go.work`; the version is derived from `git describe` and passed
via `--build-arg VERSION`:

```console
just docker-build-epa      # spilikin/zero-epa:<git-describe>            (+ :latest)
just docker-build-pdp
just docker-build-caddy    # spilikin/zero-caddy:<ver>-caddy2.11.4
just docker-push-epa       # build + push
```

For a clean image tag (`0.20.3` instead of `0.20.3-2-g…`), build from a checkout of the tag:

```console
git checkout go/epa/v0.20.3
```

## The golden rule

- **Develop** against `go.work` — local, fast, no tags, no churn.
- **Release** = push the change → `just sync` → `just tag <module> <version>` for each
  changed module → `just push-tags`. Only then do `go install` and tag-pinned Docker builds
  see the new code, because those paths bypass `go.work`.

## `just` recipe reference

| Recipe | Purpose |
| --- | --- |
| `build`, `build-<cmd>` | Build command binaries into `./dist` (version from git tag via ldflags) |
| `versions` | Show the latest tag for every module |
| `changed` | List modules with commits since their last tag |
| `tag <mod> <ver>` | Create the `go/<mod>/v<ver>` release tag |
| `push-tags` | Push all local tags to origin |
| `sync [REF=…]` | Repin in-repo requires to a branch/commit/tag tip |
| `tidy` | `go mod tidy` per module (no version changes) |
| `upgrade` | `go get -u ./...` + tidy per module (deliberate dependency upgrade) |
| `docker-build-<cmd>` / `docker-push-<cmd>` | Build / build+push the command's Docker image |
| `update-roots` | Refresh the embedded TSL root certificates |
