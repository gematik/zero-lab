---
id: decision-2
title: No OCSP relayed through the server for the web
date: '2026-10-09 13:55'
status: accepted
---
## Context

The gemiverse TSL screens and the browser Check tab report revocation as not checked: OCSP responders speak plain HTTP without CORS headers, so a browser cannot ask them, and the TSL signer's status needs a network the pure ti-wasm functions do not have.

## Decision

No OCSP request relayed through the gemiverse server, neither for the TSL signer nor for certificates checked in the browser (2026-10-04).

## Consequences

ti-wasm stays without network access; its web reports say revocation: not_checked and the TSL view keeps the no_ocsp_check warning. Do not propose a server relay again unless the requirement changes.
