# Release Notes

This lab project ist yet to yield a first release. Stay tuned!

**Every module — library and command — is versioned solely by its own git tag**
`go/<module>/vX.Y.Z`, bumped only when that module changes. There is no shared version and
no version variables. See the [Development & Release Guide](./docs/development.md) for the
step-by-step workflow.

### Local development (go.work)

The tracked `go.work` workspace resolves every in-repo module from its local source. Edit any
library (e.g. `brainpool`) and the change is immediately used by every command (e.g. `ti`)
when you build, test, or run inside the workspace — no tags, no go.mod edits.

### Versions come from git tags

Each module's version is its latest `go/<module>/vX.Y.Z` tag. `go install <cmd>@vX.Y.Z`
reports its version automatically (Go embeds the module version in the build info); local
and Docker builds stamp it from `git describe` (clean `0.20.2` on a tag, `0.20.2-3-g…` past
it, `dev` when untagged). Manage with `just versions`, `just changed`, and
`just tag <module> <version>`.

Commands are installable directly (the `@` takes the bare semver; Go maps the `go/<mod>`
subdirectory to the tag):

```
go install github.com/gematik/zero-lab/go/ti@v0.20.2
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@v0.20.2
```

`zero-caddy` combines its version with the upstream Caddy version as SemVer build metadata,
e.g. the binary reports `zero-caddy 0.20.2+caddy2.11.4` and the Docker image is tagged
`zero-caddy:0.20.2-caddy2.11.4` (`+` is illegal in Docker tags).

### Releasing a change

A tagged build (`go install`, tag-pinned Docker) runs **outside** the workspace, so a command
resolves libraries from its `go.mod`. To make a tagged build pick up a library change:

1. Edit the library; build/test/run locally (go.work uses it directly).
2. Commit and **push** the change.
3. `just sync` — repins every in-repo `require` to the branch tip (records the pushed
   commits' pseudo-versions). Commit and push the `go.mod`/`go.sum` updates.
4. `just tag <module> <version>` for each changed module (use `just changed`), then
   `just push-tags`.
5. `go install …/<cmd>@<tag>` now builds the command at its tag with the updated library code.

`just tidy` only syncs `go.mod`/`go.sum` to imports (no version changes). `just upgrade`
deliberately bumps external dependencies; after running it, re-run `just sync` before tagging.

If `proxy.golang.org` 404s a freshly pushed tag (negative cache), set
`go env -w GOPRIVATE=github.com/gematik/zero-lab` to install via direct VCS fetch.
