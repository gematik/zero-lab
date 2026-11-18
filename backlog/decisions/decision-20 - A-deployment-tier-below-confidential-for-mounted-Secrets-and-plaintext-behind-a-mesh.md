---
id: decision-20
title: >-
  A deployment tier below confidential, for mounted Secrets and plaintext behind
  a mesh
date: '2026-11-18 21:34'
status: proposed
---
## Context

docs/design/servers.md builds every server as a confidential workload. Rule 6 and decision-16 say a workload's TLS key is generated inside the workload and that a key from a cert-manager Secret or a node-local SPIRE agent does not qualify. Rule 5 ends TLS inside the workload, and rule 8 says mesh mTLS is never a workload's channel protection.

A general-purpose image has to run where none of that exists: a cluster without enclaves, with cert-manager Secrets mounted as files and a mesh that carries the pod's traffic. Rule 29 already speaks of a tier that allows or refuses plaintext, and rule 17 knows one tier decision, production, for trust material. Neither says what the tiers of a deployment are.

## Decision

Proposed, not decided. The maintainer chooses between:

1. **One tier.** Every deployment is confidential. A cluster without enclaves or an attesting issuer runs the images outside the rules, and nothing in the image or its reported configuration says so.
2. **A named second tier** (working name `standard`), which the deployment declares and the workload reports with its configuration (rule 7):
   - `standard`: key files from mounted Secrets are accepted, and `http://` on a pod address is allowed behind a mesh.
   - `confidential`: `http://` stays limited to loopback and Unix sockets, and key files come from a provisioner inside the enclave, written to a memory-backed `emptyDir`.

## Consequences

- Option 1 changes no rule. It leaves operators of ordinary clusters with a deployment the rules call wrong, and nothing to tell a confidential one from it.
- Option 2 changes rule 5 (where TLS ends) and rule 8 (mesh mTLS as channel protection) for the `standard` tier, puts the tier next to the production tier of rule 17, and amends decision-16, which then holds for `confidential` only. What `standard` may process (test data only, or production data too) has to be said with it.
- With option 2, rule 29's "refused where the tier does not allow it" gets its meaning from the tier's definition; with option 1 the sentence means loopback and Unix sockets only.
