# Development & Release Guide

This guide covers day-to-day local development against the Go workspace and how to cut
tagged, reproducible builds. All commands are run from the `go/` directory, where the
`go.work` workspace and the `Justfile` live.

## Versioning model in one minute

- **Local development** uses the tracked `go.work` workspace: every in-repo module resolves
  from local source, so a library edit is used immediately by every command — no version
  bumps, no `go.mod` edits.
- **Commands** (`zero-epa`, `zero-pdp`, `zero-caddy`, the `ti` CLI) are versioned
  independently via `go/Justfile` variables and tagged with canonical Go module tags
  (`go/<module>/vX.Y.Z`), so they are `go install`-able.
- **Libraries** are referenced by commit pseudo-versions in `go.mod`. `go install …@<tag>`
  and tag-pinned Docker builds run *outside* the workspace, so `just sync` repins the
  in-repo `require` lines to the chosen commit before tagging.
- **`zero-caddy`** reports its version plus the upstream Caddy version as SemVer build
  metadata, e.g. `zero-caddy 0.20.1+caddy2.11.4`.

The `go/Justfile` version variables are the single source of truth:

```
ZERO_VERSION       # shared version for the common library modules (ZERO_LIBS)
ZERO_EPA_VERSION   # zero-epa command
ZERO_PDP_VERSION   # zero-pdp command
ZERO_CADDY_VERSION # zero-caddy command
TI_CLI_VERSION     # ti CLI command
CADDY_VERSION      # derived from zaddy/go.mod (upstream Caddy), not edited by hand
```

## Part A — Local development (workspace)

```console
# 1. Clone and enter the workspace
git clone https://github.com/gematik/zero-lab.git
cd zero-lab/go                       # go.work lives here

# 2. Edit a library (e.g. brainpool, gempki, oauth, …)
$EDITOR brainpool/parser.go

# 3. Build / test / run — the change is already in effect via go.work
go build ./...                       # build the whole workspace
(cd brainpool && go test ./...)      # test the library you changed
(cd ti && go test ./...)             # test a consumer
go run ./ti version                  # run a command against your local libs
```

Confirm the workspace is wiring local source (not a cached module version):

```console
(cd ti && go list -m -f '{{.Path}} => {{.Dir}}' github.com/gematik/zero-lab/go/brainpool)
# => …/zero-lab/go/brainpool   (a local directory means go.work is resolving it locally)
```

Build a real binary locally with its version stamped in (it defaults to `dev` otherwise):

```console
just build-ti        # ./dist/ti  ->  "ti 0.20.1"
just build           # build all four commands into ./dist/
```

Keep modules tidy while developing (no version changes):

```console
just tidy            # go mod tidy per module
just upgrade         # ONLY when deliberately bumping external deps to latest
```

## Part B — Tag & reproducible builds

Reproducibility rests on three things: a tagged source commit, `go.mod`/`go.sum` pinned to
immutable versions, and the version stamped via `-ldflags`. Because `go install …@<tag>`
and tag-pinned Docker builds ignore `go.work`, a command's `go.mod` must point at the
library commit you want included — that is what `just sync` ensures.

```console
# 1. Land the library change first (it must be fetchable from the remote)
git add -A && git commit -m "brainpool: <change>"
git push origin <branch>

# 2. Repin in-repo requires to the branch tip so tagged/installed builds pick up
#    that library commit (local dev was already using it through go.work)
just sync                         # default REF = current branch
#   …or target a specific ref:  just sync REF=<branch|commit|tag>
git add -A && git commit -m "sync: pin in-repo deps to branch tip"
git push

# 3. If releasing new numbers, bump the version variables in go/Justfile, commit, push

# 4. Tag — canonical Go module tags (go/<module>/vX.Y.Z)
just tag                          # all four commands: go/epa, go/pdp, go/zaddy, go/ti
just tag-zero                     # optional: tag the libraries at ZERO_VERSION
just push-tags                    # push every tag to origin
```

### Reproducible install of a command

`go install` ignores `go.work` and resolves the pinned `go.mod`, so it pulls the exact
library commit synced in step 2:

```console
go install github.com/gematik/zero-lab/go/ti@v0.20.1
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@v0.20.1
ti version        # -> "ti 0.20.1"
```

### Reproducible library consumption from another project

```console
go get github.com/gematik/zero-lab/go/gempki@v0.20.1   # clean semver (after just tag-zero)
# or pin an exact commit pseudo-version for maximum reproducibility
```

### Reproducible Docker images

The build context includes `go.work`, so images build from the exact source tree; the
version is injected via `--build-arg VERSION`.

```console
just docker-build-epa      # spilikin/zero-epa:0.20.1                  (+ :latest)
just docker-build-pdp      # spilikin/zero-pdp:0.20.1
just docker-build-caddy    # spilikin/zero-caddy:0.20.1-caddy2.11.4    (our ver + Caddy ver)
just docker-push-epa       # build + push to the registry
```

For byte-reproducible images, build from a clean checkout of the tag so the source tree and
`go.sum` are fixed:

```console
git checkout go/ti/v0.20.1
```

## The golden rule

- **Develop** against `go.work` — local, fast, no version churn.
- **Release** = push libraries → `just sync` → `just tag*` → `just push-tags`. Only then do
  `go install` and tag-pinned Docker builds see the new library code, because those paths
  bypass `go.work` and read the pinned `go.mod`.

## `just` recipe reference

| Recipe | Purpose |
| --- | --- |
| `build`, `build-<cmd>` | Build command binaries locally into `./dist` (version via ldflags) |
| `tidy` | `go mod tidy` per module (no version changes) |
| `upgrade` | `go get -u ./...` + tidy per module (deliberate dependency upgrade) |
| `sync [REF=…]` | Repin in-repo requires to a branch/commit/tag tip |
| `tag`, `tag-<cmd>` | Canonical Go module release tags for the commands |
| `tag-zero` | Tag the library modules at `ZERO_VERSION` |
| `push-tags` | Push all local tags to origin |
| `docker-build-<cmd>` | Build the command's Docker image |
| `docker-push-<cmd>` | Build + push the command's Docker image |
| `update-roots` | Refresh the embedded TSL root certificates |
