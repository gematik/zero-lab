---
id: TASK-120
title: >-
  ti helpers: per-group Rust executables for Go hosts (ti-pki-helper,
  ti-idpd-helper)
status: To Do
assignee: []
created_date: '2026-10-20 14:05'
updated_date: '2026-10-20 19:55'
labels:
  - rust
  - go
  - interop
dependencies: []
priority: low
ordinal: 123000
---
## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Go programs reach the Rust core through small helper executables with hand-picked functionality instead of the universal ti, following the TASK-116 spike (spikes/go-rust-bridge on branch spike/go-rust-bridge: a long-lived Rust process answered a certificate check in 1.3 ms with a stdlib-only Go client, faster than native code loaded in process, with process isolation) and draft decision-8.

Naming (agreed with the maintainer): ti <group> -> helper ti-<group>-helper (crate and binary of the same name, rust/helpers/<group>, publish = false), protocol <group>/<n> in spec/ti-rpc, Go client go/tirpc/<group> (stdlib only), path override TI_<GROUP>_HELPER_PATH, tag rust/ti-<group>-helper/vX.Y.Z. Methods are the group's subcommands with the same names and the --format json schemas of ti; each helper offers an explicit allow-list of them and depends only on what they need. Helpers are installed in libexec/telematik/, never looked up on PATH (override, then <program dir>/../libexec/telematik, then the program's own directory); a product's release pins each helper's SHA-256 in an embedded manifest, standalone installs carry a detached ed25519 signature; every start begins with a handshake (capability, protocol, version, build).

Decisions (maintainer, 2026-10-20): wire protocol JSON lines; ti-pki-helper supports both trust modes (owned: downloads, cache and OCSP itself; supplied: the host passes TSL, roots and OCSP responses, no network); helpers are for servers and background use, so state and cache live in the standard directories and mount cleanly as container volumes (TI_STATE_DIR, TI_CACHE_DIR, TI_STORE_KEK_PATH). First helpers: ti-pki-helper and ti-idpd-helper; go/epa switches to them once the maintainer has designed the ePA local test setup.

Stages, each closed by the maintainer's HITL: 1) conventions, spec/ti-rpc, ti-rpc, ti-host, ti-pki-helper, tirpc/pki; 2) ti-idpd-helper, tirpc/idpd; 3) go/epa.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-pki-helper and ti-idpd-helper built, specified in spec/ti-rpc and reachable from Go through go/tirpc
- [ ] #2 go/epa uses the helpers instead of ti for idpd authenticate, pki verify and pki verify-signature
- [ ] #3 each stage proven by the maintainer's HITL
<!-- AC:END -->
