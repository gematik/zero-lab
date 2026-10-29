---
id: TASK-136
title: >-
  ti-cli: manage Konnektor .kon configurations: create, edit, show and test
  interactively
status: To Do
assignee: []
created_date: 2026-10-24 06:43
updated_date: '2026-10-29T06:40:00Z'
labels:
  - ti-cli
  - connector
  - security
milestone: m-0
dependencies: []
priority: medium
ordinal: 147000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Managing Konnektor configurations in ti-cli is manual today. `connector configs` lists the .kon files and `connector use` selects one, but nothing creates, edits, shows or tests a configuration. People copy and hand-edit JSON with base64 PKCS#12 data, and only the first real call tells them whether it works.

## Findings (2026-10-24)

On the maintainer's machine, ~/.config/telematik/connectors has 7 .kon files:
- **Secrets:** every one holds its password inline, and five hold the base64 PKCS#12 key inline; none uses ${NAME}. This is against docs/conventions/naming-and-config.md: secrets are read from files, never kept as values.
- **Permissions:** the files, and a .p12 next to them, are mode 0644 (any local user can read them); the directory is 0755.
- **TLS:** four set insecureSkipVerify, three have no trustStore, and two use expectedHost.

**What gemSpec_Kon V5.28.0 adds:**
- **The Konnektor's TLS identity towards client systems:** either ID.AK.AUT from the gSMC-K (A_21760-02, a Komponenten-PKI certificate whose CA is in the TSL), a renewed C.AK.AUT (A_21759), or a key and certificate generated in the Konnektor (A_21699-02) or imported by the admin (A_21697-01). The first two can be verified against the TSL with ti-pki, with no pin and no insecureSkipVerify; the last two need a pin, taken on first use (TOFU), like ssh.
- **TAB_KON_506 and TAB_KON_865:** ANCL_TLS_MANDATORY, ANCL_CAUT_MANDATORY and ANCL_CAUT_MODE decide whether TLS, client certificates or basic auth are required. The service directory (connector.sds) may be served over plain HTTP even when SOAP is not (DVD1, DVD3), so a wizard can read it before any credential.
- **Call-context errors:**
  - 4004, 4005 and 4006: unknown Mandant, client system or workplace;
  - 4010 and 4011: client system or workplace not assigned to the Mandant;
  - 4021: a required ID is missing;
  - 4204: client system not authenticated.

  Per the gemSpec_Kon error table, the first three are logged in the Konnektor, while at the external interface the client may see only 4021. A test therefore has to name all three IDs in its hint.

**Practice in other CLIs:**
- **kubectl config and docker context:** named contexts (ls, use, show, rm, import, export), with `config view` hiding secrets.
- **kubectl edit, crontab -e and visudo:** edit a temporary copy in $EDITOR and validate it before replacing the file; on error, reopen or discard, never save an invalid file.
- **gh auth and aws configure:** an interactive wizard, plus flags for scripts; `gh auth status` tests a login.
- **gh and git credential helpers:** secrets in the OS keychain or a helper, not in the config file.
- **ssh:** refuses key files other users can read (StrictModes), and shows the fingerprint for TOFU.
- **ti store doctor:** our own check report, ok, warn or fail per check, with --json.

## Proposal (to decide in the plan)

**Commands:** `ti connector config new|edit|show|test|rm|ls`, keeping `configs` and `use` as aliases.

- **`new [NAME]`:** a wizard, plus flags for agents and scripts. Steps:
  1. URL: read connector.sds.
  2. TLS: show the server certificate and classify it (ID.AK.AUT verified against the TSL, or a fingerprint to pin), and propose expectedHost when the name differs.
  3. Credentials: basic, or a PKCS#12 by path.
  4. Call context: test the IDs.
  5. Write the file atomically, mode 0600, directory 0700.
- **`edit NAME`:** $EDITOR on a 0600 temporary copy, checked before it replaces the file: reopen with the problems, or discard. Plus `config set NAME KEY=VALUE` for agents.
- **`show NAME`:** secrets redacted, shown as set, as a file reference, or as in the store.
- **`test [NAME]` ("does it work"):** checks in order, each ok, warn or fail with a hint, as text or JSON, with exit codes like `store doctor`:
  1. parse the file, and check permissions and inline secrets;
  2. DNS and TCP;
  3. the TLS handshake and the server certificate's verdict (TSL, pin or insecure), with an expiry warning;
  4. client authentication accepted (mutual TLS or basic);
  5. service directory and versions;
  6. call context, through GetCards, with the error codes above;
  7. the cards found.

  `--card` adds the PIN status.

**Secrets:** stop storing values in the .kon file; options to decide:
- **References to files** (`passwordPath`, `pkcs12Path`): the project rule.
- **The profile's sealed store** (TASK-103): no new dependency.
- **The OS keychain:** needs a new dependency (e.g. keyring), which the maintainer must approve.

Existing files keep working, and `test` warns about them; `config migrate` moves their secrets out and runs chmod.

**Hidden password input** on a terminal needs either a dependency (e.g. rpassword) or a stdin-only path, since ti forbids unsafe code: ask the maintainer.

**Related:** TASK-47 (fuzz the .kon parser; the new fields need it too) and TASK-13 (custom TLS verifier: TSL verification of ID.AK.AUT may depend on it).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Research recorded in the plan: the decisions on secret storage, TLS trust (TSL-verified ID.AK.AUT, a pin, insecure) and command names, approved by the maintainer before implementation
- [ ] #2 ti connector config new creates a working .kon interactively and from flags, written atomically with mode 0600 in a 0700 directory, with no secret values in the file
- [ ] #3 ti connector config edit opens a temporary copy in $EDITOR and never replaces the file with one that fails validation
- [ ] #4 ti connector config show redacts every secret
- [ ] #5 ti connector config test reports each check (parse and permissions, network, TLS verdict, client authentication, service directory, call context, cards) as ok, warn or fail with a hint, in text and JSON, with documented exit codes
- [ ] #6 The Konnektor's TLS certificate is verified against the TSL when it is ID.AK.AUT; otherwise it is pinned by fingerprint after confirmation; insecureSkipVerify is never proposed
- [ ] #7 Existing .kon files with inline secrets keep working, test warns about them, and a migration moves the secrets out
- [ ] #8 Tests named after the requirements (gemSpec_Kon IDs where they apply), a fuzz target for the new .kon fields, and a HITL run of new and test against a real Konnektor
- [ ] #9 ti-cli README, AGENTS.md and the Unreleased notes describe the commands
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer, 2026-10-26: in the current setup a .kon file is itself a secret (it carries credentials or key material) and is handled as one. Later: distinguish PU from non-PU configurations and make the source of the secrets in a .kon flexible, including the OS keychain.

Decisions (maintainer, 2026-10-29):
- TLS trust: always a pin of the Konnektor's server certificate; no TSL check of ID.AK.AUT (the TI-Gateway uses its own PKI anyway). new shows the certificate and pins it after confirmation; test fails on a changed certificate with that hint; no fallback to insecureSkipVerify. The existing mechanism fits: a leaf (non-CA) certificate in trustStore is already a pin by equality in ti-connector-client (KonnektorVerifier), in the format Go's tools read too. TASK-13 is no longer a dependency.
- connector.sds only over HTTPS, never HTTP. Order in new: URL, pin, credentials, SDS, call context.
- A ti GUI is planned: model, validation, redaction and the test steps with a JSON report live in a core, not in ti-cli; the CLI and the GUI are front ends over it.
- Interactive subcommands not meant for agents are allowed. Every interactive command is also fully usable through flags; it asks only when stdin is a terminal and fails with exit 2 instead of waiting otherwise. The "never a prompt" sentence in lib.rs and AGENTS.md is narrowed accordingly.
- Editing: flags and config set NAME KEY=VALUE (base, agents), a line wizard over the same steps, $EDITOR with validation before replacing for edit. No TUI (new dependency tree, a third front end next to the GUI).
- Hidden password input through rpassword 7.5.4 (+ rtoolbox 0.0.6, pinned exactly; libc, windows-sys, windows-link already in the tree), approved for ti-cli only, never a core (TASK-156: no unsafe in the cores' dependencies).
- Split: (1) core model with show and test, read-only; (2) new with pin, edit and set; (3) migrate (move inline secrets out, replace insecureSkipVerify by a pin). Secret storage stays open: better secret management is planned (TASK-104, decision-7); until then the .kon itself is a secret (0600, never printed).

Requirements (maintainer, 2026-10-29):
- insecureSkipVerify stays an option: new offers it as an explicit choice (flag --insecure-skip-verify, in the wizard only after the certificate was shown and with a warning), never as a fallback; test and show report it as warn. Open: refuse it for env pu?
- No authentication as an option: proposal "credentials": {"type": "none"}, explicit rather than an omitted credentials object, so a forgotten block stays an error. ti-connector-client's dotkon parser gets Credentials::None (today: basic or pkcs12, credentials required). Go and Kotlin clients read the same format; whether they accept type none is to be checked, and a .kon with none may be unreadable for them.

Decisions (maintainer, 2026-10-29, cont.):
- The first step of new is tolerant: a full URL, an FQDN or an IP address, with or without port or path. ti normalises to https://HOST[:PORT] (IPv6 in brackets, port 443 by default, a trailing /connector.sds or other path dropped) and shows the result before connecting. An http:// input is taken as https, never fetched over HTTP.
- insecureSkipVerify is refused for env pu (new, set, edit; test reports an existing one as fail).
- Credentials type none: the Go and Kotlin clients are extended later by the maintainer; not a blocker here.
<!-- SECTION:NOTES:END -->
