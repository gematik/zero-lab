---
id: TASK-382
title: 'docs: servers.md rules 29 and 30, transport and egress'
status: Done
assignee: []
created_date: '2026-11-18 21:34'
updated_date: '2026-11-18 21:36'
labels:
  - docs
  - servers
  - security
dependencies: []
references:
  - docs/design/servers.md
  - docs/conventions/naming-and-config.md
priority: medium
ordinal: 396000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md covers sidecar sockets (rule 8), key delivery as files (rule 6) and scheme-picks-mode (rule 17). It has no rule for listeners, transport defaults, mTLS configuration, trust sources per connection, or egress. The maintainer's change proposal of 2026-11-18 asks for: Unix sockets for listeners and peers; https as the default with certificate, key and CA bundle from files, and mTLS; plain http only as an explicit opt-out; forward proxy support for egress instead of a ban on proxy variables; trust sources broader than file paths. Documentation and backlog only: no code, no dependency. Six questions that contradict an accepted rule or decision are drafted as proposed decisions and left to the maintainer; rules 5, 6 and 23 are not edited.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 servers.md has rules 29 (one transport grammar, secure by default) and 30 (egress is a separate client) with the content of the proposal
- [x] #2 Rules 8, 17 and 26 are edited as the proposal lists; the text of rules 5, 6 and 23 is unchanged
- [x] #3 naming-and-config.md has the variable scheme for transport
- [x] #4 CLAUDE.md and every other mention of the rule count say 30
- [x] #5 Six decision records with status proposed state both options of the open questions
- [x] #6 Follow-up tasks exist for the Go profile, the PEP_ADDR migration and the Go implementation
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Rules 29 and 30 appended to servers.md with the proposal's content, regrouped after the maintainer found the first transcription undifferentiated: rule 29 has five parts (the URL is the mode; TLS from files; Unix sockets; one declared trust source per connection; reported), rule 30 four (two classes of peers; one egress client; a forward proxy as an untrusted neighbour; plain http only for self-verifying data). The three mentions of rule 7 in rule 29 are one bullet. Rule 8: the sidecar bullet points to rule 29 for the socket and keeps the peer check, because rules 27 and 29 cite 'the peer check of rule 8'. Rule 17: 'two trust sources for one connection', four more refused combinations, pointer to rule 29. Rule 26: transport tests. Rules 5, 6 and 23 untouched. naming-and-config.md: the suffix table under Environment variables. CLAUDE.md says 30 rules; no other document states the count. Proposed decisions 20 to 25 hold the six open questions with both options. Follow-ups: TASK-383 (Go profile), TASK-384 (Go implementation), TASK-385 (PEP_ADDR), TASK-386 (DATABASE_URL without prefix, found along the way). just check-changed in go/: no module changed; nothing checks the documents under docs/.
<!-- SECTION:NOTES:END -->
