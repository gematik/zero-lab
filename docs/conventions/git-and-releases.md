# Git and releases

## Branches and pull requests

- One branch per piece of work, which starts from a [backlog task](backlog.md), named
  with its kind: `feat/…`, `bugfix/…`, `chore/…`, `refactor/…` (`feat/ocsp-cache`,
  `bugfix/pkcs12-kdf-limits`).
- Changes reach `main` only through a pull request. The maintainer reviews and merges;
  nobody merges their own pull request.
- A pull request says what changed, why, and how it was verified (the checks that ran and
  their result); a change that falls short of a [principle](../principles.md) says so.
- Generated files that a change makes stale (verification stamps, traceability tables,
  lock files) are regenerated in the same pull request, never edited by hand.

## Commits

- Subject in the imperative, about 50 to 70 characters, without a type prefix; a body
  that explains why and what changed in behaviour, wrapped at 72.
- One logical change per commit; mechanical steps (a regenerated table, a dependency
  bump) may be their own commit.
- Commits and pull requests carry no tool or assistant attribution; they are the
  author's.

## Versions and tags

- **Every unit is versioned solely by its own git tag**, bumped only when that unit
  changes: `rust/<crate>/vX.Y.Z`, `go/<module>/vX.Y.Z`, and one prefix per further
  workspace. There is no shared version; an unchanged unit keeps its tag.
- Local development resolves every in-repo unit from local source (the Cargo workspace,
  `go.work`); releases are what consumers pinned to a tag see. How each workspace keeps
  sibling references in step is in its development guide.
- `just versions`, `just changed` and `just tag <unit> <version>` work the same way in
  every workspace.

## Release notes

- Each workspace has one release-notes file: `ReleaseNotes.md` at the root for Go,
  `rust/ReleaseNotes.md` for Rust. Rust keeps an "Unreleased" block per crate that every
  change adds to and a release turns into its release section; Go adds a section per
  module when it is tagged. The development guides have the details.
- Changes to licence, headers or copyright years are their own entry.

## Releasing

1. Land every change through pull requests.
2. Run every gated suite listed for the units being released
   ([testing](../design/testing.md#env-gated-tests-run-before-every-release)) and record
   the runs, or the waiver with its reason, in the release pull request.
3. The workspace's pre-release checks are green (`just audit` and what the development
   guide adds).
4. Bump, tag and push as the development guide describes; only tag-pinned consumers then
   see the new code.
