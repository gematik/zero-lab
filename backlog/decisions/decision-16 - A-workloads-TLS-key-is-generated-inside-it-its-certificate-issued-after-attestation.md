---
id: decision-16
title: >-
  A workload's TLS key is generated inside it, its certificate issued after
  attestation
date: '2026-11-12T21:18:00Z'
status: accepted
---
## Context

The maintainer's OPA container-image pattern (2026-11-12, TASK-302) takes TLS certificates from cert-manager (a Secret mounted as files) or the SPIRE Workload API, and calls the SPIRE key "in memory only". Under docs/design/servers.md rules 4 and 6 neither holds for a confidential workload: cert-manager generates the key in a controller outside the enclave and keeps it in a Secret in the control plane, and a SPIRE agent runs on the node, outside the enclave, and generates the SVID key in the untrusted host's memory.

## Decision

Maintainer, 2026-11-12: a workload's TLS key is generated inside the workload, and a certificate for it is issued only after the workload's attestation is verified: a CSR bound to the attestation evidence, or SPIRE with a TEE node attestor and its agent inside the confidential VM. cert-manager Secrets and node-local SPIRE agents do not provide workload keys.

## Consequences

- servers.md rule 6 states it; rotation renews the certificate the same way, without a restart of the workload or its sidecars.
- A deployment needs an issuer that verifies attestation (a key broker or attesting CA, or SPIRE with a TEE attestor); a plain cert-manager setup no longer qualifies.
- Sidecars without such a client get their certificate from the workload's own provisioning, inside the enclave, never from a host-side agent.
