# Text for agents

How the tools of this repository describe themselves to AI agents and scripts, and what an
agent may do with them. The reasons are in
[decision-9](../../backlog/decisions/decision-9%20-%20Agent-skills-are-entry-points-to-the-tools-own-guides.md).
Rules for agents that develop this repository are in [`CLAUDE.md`](../../CLAUDE.md), not
here.

## One guide per tool

- Every CLI owns one guide, `AGENTS.md` next to its sources
  ([`rust/ti-cli/AGENTS.md`](../../rust/ti-cli/AGENTS.md)). It is the only description of
  what the tool does and how to call it; nothing restates it, in a skill, a README or a
  prompt. A README links to it.
- The guide is embedded in the binary and printed by `<bin> agent`, so an agent reads the
  version it runs, offline. `{bin}` in the guide stands for the executable's name.
- The guide states the calling conventions every command shares: the JSON output and its
  schema version, where the schema of each command comes from (`<bin> schema`), the exit
  codes, the error document on stderr and its `kind`s. Details of one command stay in its
  `--help` and its schema; the guide names the commands and what an agent must know
  beyond them.
- A change to a command's behaviour, output, exit code or error kind changes the guide
  in the same commit. A difference between the guide and the binary is a bug.

## Skills

- A skill is an entry point to a tool's guide, not a second copy of it. It holds the
  trigger (when to use the tool), the entry point (how to reach the guide) and, for use
  without the binary, a generated reference. It holds no command catalogue, exit-code
  table, error kinds or recipes of its own; what the guide lacks goes into the guide.
- Usage skills live flat in `skills/`: a `zero-lab` skill that names the tool for a
  task, and one skill per tool (`skills/ti`, `skills/zero-epa`, …). Skills for developing
  this repository live in `.agents/skills/`. A usage skill does not trigger on work on
  the tool itself.
- `references/AGENTS.md` in a tool's skill is generated from the tool's guide, names the
  version it was generated from, and is never edited by hand; `just check` fails on a
  difference.

## Two modes

- **With the binary**, as for a local agent: the skill runs `<bin> agent` and follows it,
  then `<bin> COMMAND --help` and `<bin> schema COMMAND` for a command's details.
- **Without the binary**, as in a web chat whose sandbox has no tool, no Konnektor, no
  card and no TI network: the skill reads `references/AGENTS.md` and runs nothing. It
  explains, reads output the user pastes, and gives the user commands to run locally. It
  says which released version it describes, which may differ from the one the user has
  installed.

## What agents do with the tools

These rules hold for every tool and are stated in each guide and skill that needs them.

- **Secrets:** an agent never asks for a real `.kon` file, PKCS#12 file, PIN, client
  secret or token, and never prints one; it refers to them by path. A `.kon` file is a
  secret as a whole: it holds the Konnektor's credentials. Samples with placeholders, for
  creating or editing a file, are allowed.
- **Pasted secrets:** when a user pastes one, the agent says it should not have been
  shared and should be replaced where that is possible, and does not repeat it, quote it
  or carry it into commands or files.
- **PINs and cards:** commands that ask for a PIN at the card terminal, or use up a try,
  run only when the user asks for that step; the agent says before what the user will be
  asked for.
- **Output:** an agent asks for JSON (`--format json`), branches on the exit code and
  the error's `kind`, never on a message, and ignores fields it does not know.
