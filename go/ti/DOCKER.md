# Building `ti` in a Dockerfile

Notes for building the `ti` CLI into a container image. The repository layout has a few
traps that are not obvious from inside `go/ti/`.

## What makes this repo different

`go/ti` is one module among many in `github.com/gematik/zero-lab`. Its siblings — `kon`,
`epa`, `gemidp`, `gempki`, `brainpool`, `pkcs12` — are separate modules, resolved either
from the `go/go.work` workspace (local source) or from their pinned versions in
`ti/go.mod`. Which of the two you get decides whether your image contains local changes.

Every module is versioned by its own git tag, `go/<module>/vX.Y.Z`. There is no repo-wide
version.

## Option 1 — build from the repo (picks up local changes)

The build context must be `go/`, not `go/ti/`, so that `go.work` and the sibling modules
are visible. This mirrors `epa/cmd/zero-epa/Dockerfile` and the other images here.

```dockerfile
FROM golang:1.26 AS build

ARG VERSION=dev

WORKDIR /src
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build \
	-ldflags "-X github.com/gematik/zero-lab/go/ti/internal/common.Version=${VERSION}" \
	-o /out/ti ./ti

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ti /usr/local/bin/ti

ENV XDG_CONFIG_HOME=/config
ENTRYPOINT ["ti"]
```

Build it from `go/`:

```bash
docker build --build-arg VERSION="$(just _modver ti)" -f ti/Dockerfile -t ti:dev .
```

`go.work` is committed, so `go build ./ti` inside the image resolves `kon` and the other
siblings from `/src`, ignoring the versions pinned in `ti/go.mod`.

## Option 2 — build a released version (no repo checkout)

Tagged builds ignore `go.work` and use the versions pinned in `ti/go.mod` at that tag. Pin
an exact tag; `@latest` makes the image non-reproducible.

```dockerfile
FROM golang:1.26 AS build
RUN CGO_ENABLED=0 GOOS=linux go install github.com/gematik/zero-lab/go/ti@v0.20.6
```

No `-ldflags` needed here — `ti version` falls back to the module version Go embeds in the
build info.

If you take this route and the fix you need lives in a sibling module, make sure the
sibling change was pushed and `just sync` was run and committed *before* the `ti` tag,
otherwise the tag still pins the old sibling code.

## Details that bite

- **Build context is `go/`.** From `go/ti/` the sibling modules and `go.work` are outside
  the context and the build fails to resolve them.
- **`CGO_ENABLED=0` is fine.** The only C-looking dependency, SQLite, is `modernc.org/sqlite`
  (pure Go), so static builds and `scratch`/`distroless` bases work.
- **Version stamping targets `internal/common`,** not `main`:
  `-X github.com/gematik/zero-lab/go/ti/internal/common.Version=<v>`. A wrong path is
  silently ignored by the linker and `ti version` prints `dev`.
- **CA certificates are required at runtime.** `ti` talks HTTPS to connectors, IDPs and ePA
  providers. On `scratch`, copy `/etc/ssl` from the build stage.
- **`ti` needs a writable config dir.** State (selected connector, ePA caches, TSL cache,
  `cli-state.db`) goes to `$XDG_CONFIG_HOME/telematik`. Set `XDG_CONFIG_HOME` to a mounted
  volume, or the CLI writes into the container's ephemeral filesystem.
- **Connector credentials are not baked in.** Mount the `.kon` file and pass its path via
  `-c` or `TI_CONNECTOR_CONFIG`. The file supports `${ENV_VAR}` expansion, so secrets can
  stay in the environment rather than in the image.
- **mTLS to a connector needs the client certificate at runtime** too — another mount, not
  an image layer.

## Smoke test

```bash
docker run --rm ti:dev version
docker run --rm ti:dev connector configs
docker run --rm -v "$HOME/.config/telematik:/config" ti:dev connector get info
```

The first must print the version you passed as `VERSION` (or the module version for
Option 2) — if it prints `dev`, the `-ldflags` path is wrong. The second exercises the
config dir without needing a connector; the third needs a configured one under the mount.
