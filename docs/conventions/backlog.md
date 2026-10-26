# Backlog

Open work for the whole repository, Rust, Go and cross-language alike, lives in one
backlog: [`backlog/`](../../backlog/) at the repository root, managed with the
[Backlog.md](https://github.com/MrLesk/Backlog.md) CLI. Run `backlog` from the repository
root; its configuration is `backlog/config.yml`. Tasks are Markdown files in git.

## Where task changes land

- Task files change on `main`, or on a branch that merges soon, such as the branch whose
  pull request completes the task. Creating, planning and reprioritising tasks goes to
  `main` directly; it is the one change that does not need a pull request.
- A long-lived branch carries no task changes. The CLI reads only the current branch
  (`check_active_branches: false`), so a task changed elsewhere is invisible until it
  merges.

## What goes into the backlog

- **Every piece of work before it starts:** a feature, a fix, a refactoring, a release, a
  housekeeping step. Work starts from a task, not from memory.
- **Every gap against the rules** in [docs](../README.md): the documents state rules
  only, and a place where the code falls short is a task.
- **Findings along the way:** a bug, a risk or a follow-up found while working on
  something else becomes its own task instead of widening the current change.
- **Decisions** that settle a question for good go to `backlog decision`; longer
  background goes to `backlog doc`.

## Writing a task

- **Title:** what is to be achieved, prefixed by the unit when there is one
  (`ti-pki: …`, `Go: …`, `pdp: …`).
- **Description:** why, with the facts that make the problem concrete (file, function,
  measurement), and the rule or requirement it serves.
- **Acceptance criteria:** observable outcomes a reviewer can check, one per line; not
  steps.
- **Labels:** the unit (`ti-pki`, `jwz`, `go`, `pdp`, …) and the kind (`fuzz`, `tests`,
  `deps`, `keys`, `spec`, `security`, `release`, `chore`, …), in the spelling existing
  tasks use.
- **Priority:** `high` for security defects, release blockers and broken checks;
  `medium` for gaps against the rules and planned work; `low` for nice-to-have and
  housekeeping.
- **References:** the document of the rule (`docs/…`), the language profile, the spec
  rule or gematik requirement.
- **Dependencies:** a task depends on what must be finished first, never the other way
  round.

## Working a task

1. Find or create the task (`backlog task list --plain`, `backlog search <words>`); one
   branch per task.
2. Set it to `In Progress` when work starts; write the plan into the task for anything
   larger than a small fix.
3. Record what you learned and decided as implementation notes while working, not at the
   end from memory.
4. Tick each acceptance criterion when it is met; adjust criteria only openly, with the
   reason in the notes.
5. Set it to `Done` with a final summary (what changed, how it was verified, what was
   left out and where it went) in the pull request that completes it.

Use the CLI for every change it supports, so files stay in the format it reads; edit a
file by hand only for what the CLI cannot do (such as removing a dependency), keeping
its structure.
