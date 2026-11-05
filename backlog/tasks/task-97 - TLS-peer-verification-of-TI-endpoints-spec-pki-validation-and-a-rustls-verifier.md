---
id: TASK-97
title: 'TLS server verification as core hooks: TI-PKI and hardened Web-PKI'
status: To Do
assignee: []
created_date: 2026-10-15 05:20
updated_date: '2026-11-05T19:31:00Z'
labels:
  - ti-pki
  - spec
  - keys
dependencies: []
references:
  - docs/architecture.md
  - rust/docs/design.md
priority: medium
ordinal: 95000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The host owns the transport, the core owns trust (docs/architecture.md). Today a host verifies TLS servers with its own stack and the system store; the Konnektor adapter is the one exception. This task gives every host two verification profiles, each as a hook it plugs into its TLS stack.

**TI-PKI server certificates** (TI endpoints, e.g. the ePA aggregators, whose certificates come from GEM.KOMP-CA): trust only from the verified TSL and roots.json through ti-pki, never the system store; the validation profile of the certificate type; the algorithms and key sizes the gematik rules allow; OCSP as gemSpec_PKI requires, stapled or fetched, with its freshness; the host name from the SAN.

**Web-PKI server certificates** (internet endpoints, e.g. OpenID Federation masters and providers, gematik's dev gateways), hardened beyond what a browser accepts: a curated root set instead of the system store; TLS 1.3, or 1.2 with AEAD suites only; no SHA-1 and minimum key sizes; serverAuth EKU; a validity limit; Certificate Transparency and revocation as the spec decides.

Which profile an endpoint gets is core configuration, never inferred from its certificate, and neither profile falls back to the other or to the system store.

**Hooks, secure and fast.** A hook fails closed and cannot be configured to skip a check. The trust material is an immutable snapshot, indexed once and swapped atomically on refresh, so a handshake takes no lock and builds no index. Verdicts are cached, keyed by the chain's hash, the server name and the profile, and bounded by the earliest of notAfter, the OCSP response's nextUpdate and the snapshot's age. A cached verdict can never outlive a reason to refuse, and OCSP is fetched off the handshake's critical path where the rules allow. The clock is injected.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/pki-validation defines both profiles: rules with requirement IDs (gemSpec_PKI for TI-PKI, RFC 5280, CA/B Forum and the chosen hardening for Web-PKI), result codes, and a corpus with negative cases for each rule
- [ ] #2 ti-pki supplies both profiles as rustls ServerCertVerifiers over a shared, atomically swapped trust snapshot and a bounded verdict cache; the corpus passes; any new parser has a fuzz target
- [ ] #3 Benchmarks with a budget for a cold and a cached verification of each profile, checked by a just recipe
- [ ] #4 The ureq and reqwest adapters and ti-cli take the profile per endpoint from configuration, with no fallback to the system store; the Konnektor's .kon pinning stays as it is
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-05, maintainer: TI-PKI server certificates and hardened Web-PKI server certificates are two profiles; the hooks must be secure and fast. The earlier note about the PDP's token exchange (TASK-168) and the relying parties (TASK-171) is gone with those tasks.
<!-- SECTION:NOTES:END -->
