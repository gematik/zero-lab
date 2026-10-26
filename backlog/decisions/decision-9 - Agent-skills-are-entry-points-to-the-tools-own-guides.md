---
id: decision-9
title: Agent skills are entry points to the tools' own guides
date: '2026-10-26 11:07'
status: proposed
---
## Context

`ti agent` prints `rust/ti-cli/AGENTS.md`, embedded in the binary, so an agent learns the version it runs. PR #75 proposed a skill that restated it in snippets and tables; they had drifted before the PR was reviewed (exit codes, Bestandsnetze, Konnektor fault hints). Skills for every CLI of the repository are planned, and they run in two settings: a local agent with the tool installed, and a web chat whose sandbox has no tool, no Konnektor, no card and no TI network, where real TI material must not go.

## Decision

1. Each CLI owns one guide for agents, its `AGENTS.md`, embedded in the binary and printed by `<bin> agent`. It is the only source of what the tool does and how to use it.
2. Usage skills live flat in `skills/`: a `zero-lab` router skill that names the tool for a task, and one skill per tool (`skills/ti`, `skills/zero-epa`, …). Development skills for working in this repository live in `.agents/skills/`. A usage skill does not trigger on developing the tool.
3. A tool skill is an entry point with two modes. With the binary present it runs `<bin> agent` and follows it, then `--help` and `schema`. Without it, as in a web chat, it reads `references/AGENTS.md` and runs nothing; it explains, interprets output and gives the user commands to run locally.
4. `references/AGENTS.md` is generated from the tool's `AGENTS.md`, states the version it describes, and is never edited by hand; `just check` fails on a difference. A release attaches the skill as a ZIP for upload.
5. Agents never ask for real `.kon` files, PKCS#12 files, PINs or tokens, never print them, and do not repeat one a user pasted. Samples with placeholders are allowed.
6. `docs/conventions/agents.md` owns these rules.

## Consequences

- TASK-142 writes the convention; TASK-143 gives the Go CLIs `agent`; TASK-144 builds `skills/` and its check; TASK-145 adds the skill ZIP to releases. TASK-141 (PR #75) becomes `skills/ti` under this layout.
- The generated reference is a second copy on disk, accepted because it is generated and checked, and because a web chat cannot run the binary.
- A web-chat skill describes the released version it was built from, not the user's installed one; it says so.
