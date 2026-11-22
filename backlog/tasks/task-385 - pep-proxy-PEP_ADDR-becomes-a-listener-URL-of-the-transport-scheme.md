---
id: TASK-385
title: 'pep/proxy: PEP_ADDR becomes a listener URL of the transport scheme'
status: Done
assignee: []
created_date: '2026-11-18 21:34'
updated_date: '2026-11-22 14:13'
labels:
  - pep-proxy
  - go
  - config
dependencies:
  - TASK-384
references:
  - docs/conventions/naming-and-config.md
priority: medium
ordinal: 399000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
naming-and-config.md gains the variable scheme for transport (TASK-382): <COMPONENT>_<NAME>_URL with the scheme as the mode, and …_TLS_CERT_PATH, …_TLS_KEY_PATH, …_TLS_CA_PATH, …_TLS_PEER_NAME. PEP_ADDR (go/pep/proxy/cmd/zero-pep-proxy/main.go:200, default :4180; CONFIG.md, DOCKERHUB.md, docker-compose.yaml, e2e/README.md) is the only listener variable in the Go code today and is a bare address without a scheme. It was deliberately not renamed with the rule.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 zero-pep-proxy reads its listener from a variable of the scheme; PEP_ADDR is refused or migrated as the release notes say
- [x] #2 CONFIG.md, DOCKERHUB.md, the compose file and the e2e guide use the new variable
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy reads its listener from PEP_LISTEN_URL (servers.md rule 29); PEP_ADDR is refused at start with the migration hint, and an unset PEP_LISTEN_URL stops the start with the three recommended forms. CONFIG.md, DOCKERHUB.md, the compose file and the e2e guide use the new variables. For the next release (breaking): zero-lab-k8s's chart sets PEP_ADDR and must set PEP_LISTEN_URL=http://0.0.0.0:4180 with PEP_LISTEN_PLAINTEXT_ACCEPTED=true behind its Caddy edge.
<!-- SECTION:FINAL_SUMMARY:END -->
