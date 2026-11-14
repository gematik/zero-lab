---
id: TASK-317
title: 'oidf: key files are read by the host, not the library'
status: To Do
assignee: []
created_date: '2026-11-14T20:52:00Z'
labels:
  - oidf
  - go
  - keys
dependencies: []
ordinal: 332000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
NewRelyingParty reads PEM and JWK key files and accepts an inline private JWK in its configuration (relying_party.go loadKeyConfig, parseKeySource). That is the no-ambient-I/O gap decision-13 names for oidf, and an inline JWK with d in configuration is against docs/design/keys.md rule 1. Since TASK-315 the library takes its keys through New(ctx, cfg, Keys) as crypto.Signer, an ECDH key agreement and a tls.Certificate; the loading can move to the hosts (zero-pdp, zero-pep-proxy) and the inline private JWK go. Found while planning TASK-315.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 oidf reads no file; the hosts load the keys and call New; configuration carries no private key
<!-- AC:END -->
