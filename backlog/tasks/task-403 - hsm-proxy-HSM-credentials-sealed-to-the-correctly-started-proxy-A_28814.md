---
id: TASK-403
title: 'hsm-proxy: HSM credentials sealed to the correctly started proxy (A_28814)'
status: To Do
assignee: []
created_date: '2026-11-20 07:53'
labels:
  - rust
  - hsm
  - security
dependencies:
  - TASK-389
references:
  - rust/ti-hsm-proxy
  - docs/design/servers.md
priority: medium
ordinal: 416000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
gemSpec_ZETA A_28747 lets the ZETA keys be used only through an HSM proxy attested to the HSM or paired with it in a documented key ceremony; the sidecar takes the pairing (README, Attestation to the HSM). A_28814: paired, the proxy must seal its local access credentials so that after a restart only correctly started processing contexts of the proxy have them. Today hsm-proxy reads the user PIN from HSM_PROXY_USER_PIN_PATH, a file. servers.md rule 6 already asks that keys and secrets be released to a workload only after its attestation is verified, by a key broker with a release policy on the measurement, delivered as files. To decide and build: how the PIN (or the vendor's partition credential) is sealed: released by the key broker on the sidecar's attestation, or sealed to the confidential VM's measurement (vTPM, TDX/SEV-SNP sealing), and how the key ceremony that pairs proxy and HSM is documented.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The HSM credentials reach the sidecar only when its start state is attested, by a key broker or by sealing to the measurement; a changed image or configuration does not get them
- [ ] #2 A document describes the key ceremony that pairs a proxy with an HSM (partition), as A_28747 asks
<!-- AC:END -->
