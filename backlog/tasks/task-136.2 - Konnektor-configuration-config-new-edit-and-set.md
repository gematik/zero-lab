---
id: TASK-136.2
title: 'Konnektor configuration: config new, edit and set'
status: To Do
assignee: []
created_date: '2026-10-29T06:44:00Z'
updated_date: '2026-10-29T06:48:00Z'
labels:
  - ti-cli
  - connector
  - security
milestone: m-0
dependencies: []
parent_task_id: TASK-136
priority: medium
ordinal: 166000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Second part of TASK-136, on the core of the first. Decisions in TASK-136's notes; rpassword 7.5.4 with rtoolbox 0.0.6 is approved for ti-cli only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 config new asks only when stdin is a terminal and is fully usable through flags; without a terminal and with missing flags it fails with exit 2 instead of waiting; lib.rs and AGENTS.md narrow the "never a prompt" rule accordingly
- [ ] #2 The address accepts an https URL, FQDN, FQDN:PORT, IP, IP:PORT, [IPv6] and [IPv6]:PORT, optionally with a path, normalises to https://HOST[:PORT] and shows it; http:// is an error with exit 2
- [ ] #3 The server certificate is shown (subject, issuer, validity, SHA-256) and stored as a pin in trustStore after confirmation; without confirmation or --pin-file nothing is trusted; insecureSkipVerify only as an explicit choice after the certificate was shown, never as a fallback
- [ ] #4 Credentials basic, pkcs12 or none; passwords hidden through rpassword in the wizard, from files only through flags; a .p12 is decoded locally and its contents shown, with warnings for expiry, legacy encryption, unsuitable key type and a file readable by others; with several pairs the user chooses
- [ ] #5 connector.sds is read over HTTPS only, after pin and credentials; the call context is tested before saving
- [ ] #6 new, edit and set refuse insecureSkipVerify and credentials type none for env pu
- [ ] #7 The file is written atomically with mode 0600 in a directory with mode 0700; secrets are never printed
- [ ] #8 config edit NAME opens a copy in $EDITOR and replaces the file only after validation; config edit NAME --p12 FILE replaces the client certificate and keeps pin and context; config set NAME KEY=VALUE changes one field
- [ ] #9 Tests named after the requirement each proves, including the non-interactive paths and the PU refusals
- [ ] #10 config pin NAME renews the pin: it shows the server's current certificate next to the pinned one (subject, issuer, validity, SHA-256), replaces the pin only after confirmation (or with --pin-file) and leaves insecureSkipVerify untouched; config test's hint on a changed certificate names this command
<!-- AC:END -->
