---
id: TASK-317
title: 'oidf: key files are read by the host, not the library'
status: Done
assignee: []
created_date: '2026-11-14T20:52:00Z'
updated_date: '2026-11-15T11:13:00Z'
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
- [x] #1 oidf reads no file; the hosts load the keys and call New; configuration carries no private key
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
oidf reads no file and takes no inline private JWK: Kind takes the host's key loader for KeyFiles (key_pem_path, cert_pem_path, kid, YAML shape unchanged), zero-pdp and zero-pep-proxy load one PEM key per file. Breaking: NewRelyingParty and KeyConfig removed, Kind's signature, jwk/jwk_path gone, RSA refused, pdp Config.OIDFKeys. Merged at d8f24089.
<!-- SECTION:FINAL_SUMMARY:END -->
