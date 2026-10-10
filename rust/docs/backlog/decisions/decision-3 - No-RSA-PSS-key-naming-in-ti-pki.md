---
id: decision-3
title: No RSA-PSS key naming in ti-pki
date: '2026-10-09 13:55'
status: accepted
---
## Context

One production TSL certificate has an RSASSA-PSS key; ti-pki's key classification shows it as the bare OID 1.2.840.113549.1.1.10 and rates it not admissible.

## Decision

ti-pki does not get a name for RSA-PSS keys (2026-10-04).

## Consequences

The OID stays as shown; do not propose naming it again.
