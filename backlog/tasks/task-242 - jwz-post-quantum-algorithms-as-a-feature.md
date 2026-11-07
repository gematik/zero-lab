---
id: TASK-242
title: 'jwz: post-quantum algorithms as a feature'
status: To Do
assignee: []
created_date: '2026-11-07T10:52:00Z'
labels:
  - jwz
  - pqc
dependencies: []
ordinal: 258000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Post-quantum signatures and key establishment in jwz behind a cargo feature (off by default), so that a host opts in and the default build keeps its dependency tree. Candidates: ML-DSA for JWS (FIPS 204; IETF draft-ietf-cose-dilithium, which registers ML-DSA-44/65/87 and the AKP key type for JOSE and COSE) and ML-KEM for JWE (FIPS 203; draft-ietf-jose-pqc-kem, and hybrid variants). Check the drafts' state and the BSI/gematik guidance (TR-02102, gemSpec_Krypt) before choosing; drafts move, so pin the version implemented. Backends: RustCrypto's ml-dsa and ml-kem crates (pre-1.0) are the natural fit for the pure-Rust backend; adding them needs the maintainer's consent under docs/conventions/dependencies.md (unsafe, transitive cost, maintenance, cargo vet). Keys as functions and the async signer traits must cover the new algorithms, for HSMs that hold ML-DSA keys.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a decision, recorded in ADR 0001, on which algorithms and which draft versions, the feature name and the backend dependencies, agreed with the maintainer
- [ ] #2 the chosen algorithms sign/verify or encrypt/decrypt behind the feature through the backend traits, with the drafts' examples as known-answer tests, a traceability entry per requirement, and fuzz coverage of any new key parser
- [ ] #3 the default build and its dependency tree are unchanged; the feature builds for wasm32-unknown-unknown and its tests run there
<!-- AC:END -->
