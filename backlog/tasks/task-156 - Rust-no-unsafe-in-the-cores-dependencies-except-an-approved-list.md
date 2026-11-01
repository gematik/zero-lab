---
id: TASK-156
title: 'Rust: no unsafe in the cores'' dependencies except an approved list'
status: Done
assignee: []
created_date: '2026-10-29T06:33:00Z'
updated_date: '2026-10-29T12:31:00Z'
labels:
  - rust
  - security
  - dependencies
milestone: m-0
dependencies: []
priority: medium
ordinal: 164000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Maintainer rule (2026-10-29): a core crate carries no `unsafe`, also not through its dependencies. Crates that need `unsafe` (terminal, OS, FFI; e.g. rpassword for TASK-136) belong to the host (ti-cli), never to a core. Exceptions only on an approved list.

Today the workspace's `unsafe_code = "forbid"` (rust/docs/design.md) covers our own code only. The cores' normal trees (ti-pki, ti-connector-client without its ureq feature, ti-idpd, ti-directory, jwz, jwz-brainpool, ti-jwz, ti-xmldsig, ti-pkcs12, ti-report) already contain crates with `unsafe`, among them libc, getrandom, cpufeatures, zeroize, hybrid-array, memchr, aes, ghash/polyval, curve25519-dalek, crypto-bigint, ctutils/cmov. ti-types and ti-store are free of it.

Which crates are cores and which are hosts is decided in the task (ti-cli, ti-wasm's glue and adapter features such as ti-connector-client/ureq or ti-pki's reqwest adapter are hosts).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The rule is in the document it belongs to (rust/docs/design.md, the dependencies convention if it is language-independent), with what counts as a core, what as a host, and how an exception is approved
- [x] #2 An inventory of every crate with `unsafe` in each core's normal dependency tree (all non-host features), with why it needs it (intrinsics, volatile zeroing, system calls, ...)
- [x] #3 An exception list in the repository, each entry with crate, reason and approval date; the maintainer has approved the initial list
- [x] #4 Crates that cannot be justified are replaced or moved behind a host feature, each as its own task
- [x] #5 A just check recipe fails when a core's tree gains a crate with `unsafe` that is not on the list, also for a new version of a listed crate that is checked again; it is part of just check
- [x] #6 The dependency proposal template for agents says whether a crate contains `unsafe` and in which crate it would land
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Freigegeben 2026-10-29: (1) Kerne ti-types, ti-store, ti-xmldsig, ti-pki, ti-pkcs12, ti-connector-client, ti-report, jwz, jwz-brainpool, ti-jwz, ti-idpd, ti-directory; Hosts ti-cli, ti-wasm; Host-Features ti-pki reqwest/tokio, ti-connector-client und ti-idpd ureq, ti-types clap, überall test-util. (2) Nur Laufzeit: normale Kanten ohne Proc-Macros und Build-Skripte; Ziele aarch64-apple-darwin, x86_64-unknown-linux-musl, x86_64-pc-windows-gnu, wasm32-unknown-unknown. (3) Werkzeug: Rust-Bin im Workspace (publish=false), cargo tree je Kern und Ziel, syn (full, visit) zählt unsafe-Blöcke, -fn, -impl, -trait, extern-Blöcke und unsafe in Makro-Tokens. (4) Liste rust/docs/unsafe-exceptions.md: Crate, exakte Version, Grund, Freigabedatum; neue Version scheitert bis zur Prüfung; in just check. (5) Startliste als Ganzes freigeben; Ersatzkandidaten als eigene Tasks; Regel in rust/docs/design.md, Vorschlagsvorlage um unsafe ergänzt.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Input from TASK-136.1 (2026-10-29): ti-pkcs12 is a regular dependency of ti-connector-client since then (for the redacted view and the client-certificate check), bringing pkcs5, cbc, des, rc2, hmac, sha1 into its core tree; part of the inventory.

Umsetzung 2026-10-29: Regel in rust/docs/design.md Abschnitt 8 (Kerne, Hosts, Host-Features, Ziele, Freigabe); Vorlage in docs/conventions/dependencies.md Regel 7 und CLAUDE.md (unsafe? Kern oder Host?). Werkzeug rust/unsafe-audit (publish=false; syn 3.0.6 full/visit, proc-macro2, quote, alles schon im Lockfile): cargo tree je Kern und Ziel (normal, ohne Proc-Macros und Build-Skripte), syn zählt block/fn/impl/trait/extern/macro/attribute; check scheitert bei nicht gelisteter Crate, anderer Version und überflüssiger Zeile (vorgeführt), inventory listet die Stellen; just unsafe-free in just check (~10 s). Bestand: 84 Crates, 36 mit unsafe, alle mit Grund in rust/docs/unsafe-exceptions.md. Ersatz: base64 → TASK-159 (neu), arc-swap → TASK-58, scrypt → TASK-56; die übrigen sind Krypto-Intrinsics, Zufallsquelle, repr(transparent)-Casts und unchecked UTF-8 der Encoder, wasm-only (wasm-bindgen, once_cell, unicode-ident über getrandom wasm_js). Offen: AC3, Freigabe der Startliste durch den Maintainer.

Startliste (36 Crates) am 2026-10-29 vom Maintainer freigegeben.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Regel 'kein unsafe in den Kernen, auch nicht in Abhängigkeiten' in rust/docs/design.md §8; Ausnahmeliste rust/docs/unsafe-exceptions.md (36 Crates mit exakter Version, Grund, Freigabe 2026-10-29); rust/unsafe-audit (syn) prüft per just unsafe-free in just check: nicht gelistete Crate, andere Version, überflüssige Zeile scheitern. Vorschlagsvorlage (dependencies.md Regel 7, CLAUDE.md) fragt nach unsafe und Kern/Host. Ersatz-Tasks: TASK-159 (base64), TASK-58 (arc-swap), TASK-56 (scrypt).
<!-- SECTION:FINAL_SUMMARY:END -->
