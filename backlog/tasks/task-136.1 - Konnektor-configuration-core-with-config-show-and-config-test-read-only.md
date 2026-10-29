---
id: TASK-136.1
title: Konnektor configuration core with config show and config test (read-only)
status: To Do
assignee: []
created_date: '2026-10-29T06:44:00Z'
labels:
  - ti-cli
  - connector
  - security
milestone: m-0
dependencies: []
parent_task_id: TASK-136
priority: medium
ordinal: 165000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First part of TASK-136. A core module (not in ti-cli, so the planned GUI uses it too) with the .kon model, validation, redaction and the test steps with a JSON report; ti-cli's config show and config test as front ends. Decisions in TASK-136's notes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The model, validation, redaction and test steps live in a core (ti-connector-client or a new crate, decided in the plan) under the workspace lints, with no dependency that contains unsafe outside the TASK-156 list
- [ ] #2 The .kon parser accepts credentials type none (Credentials::None: no client certificate, no Authorization header); unsupported types still fail
- [ ] #3 config show NAME prints the configuration with every secret redacted, text and JSON; a JSON schema describes it
- [ ] #4 config test NAME runs file (mode, plain-text secrets), DNS/TCP, TLS with the pin or insecureSkipVerify, client authentication, connector.sds over HTTPS, versions, call context and card list in order, each ok, warn or fail with a hint; a JSON schema describes the report
- [ ] #5 test reports insecureSkipVerify and credentials type none as fail for env pu and as warn otherwise; the parser does not refuse them on load
- [ ] #6 The call-context errors 4004, 4005, 4006, 4010, 4011, 4021 and 4204 lead to hints naming mandant, client system and workplace
- [ ] #7 connector configs and connector use keep working; AGENTS.md and the help describe the new commands
- [ ] #8 Tests named after the requirement each proves, against a local Konnektor stub; the new parser parts are covered by the .kon fuzz target (TASK-47)
<!-- AC:END -->
