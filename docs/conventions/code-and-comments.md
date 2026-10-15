# Code and comments

## Licence and headers

- All code is EUPL-1.2. Every source file gematik writes starts with the EUPL licence
  header the existing files of its language use (`Copyright (Change Date see Readme),
  gematik GmbH`), as the gematik OSPO rules require; the year range lives in the root
  README's License section.
- Third-party code and data keep their own licence and header; generated code carries
  none.

## Comments

- Comments explain why: intent, trade-offs, non-obvious constraints, the requirement a
  piece of code implements (`P12-036: …`, `RFC 7516 §5.2: …`).
- They never restate what the code does, describe the change or the request that led to
  it, or carry changelogs, TODO lists or attribution; history belongs in git and open
  work in the backlog.
- Public items are documented; the language profiles name the lint that enforces it.

## Style

- Write code as the surrounding code is written: its naming, idiom and comment density.
- Formatting is the language's standard formatter with the repository's configuration;
  a check fails on unformatted code.
- Prefer clear code over clever code; security-relevant code is written to be reviewed.
- Errors carry the reason a reviewer and a caller need, and map to the result codes of the
  specification the code implements.
