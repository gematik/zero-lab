---
id: TASK-392
title: >-
  ti pki verify: the chain view runs through a self-signed root to its
  cross-certificate
status: Done
assignee: []
created_date: '2026-11-19 12:42'
updated_date: '2026-11-23 05:56'
labels:
  - rust
  - pki
  - cli
dependencies: []
references:
  - rust/ti-cli/src/commands/inspect.rs
priority: low
ordinal: 405000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed 2026-11-19 with ti-cli 0.6.2 against dienst.vsdd2.ru.service-ti.de. The server sends five certificates: the leaf, GeoTrust G5 TLS ECC P-384 SHA384 2022 CA2, the self-signed DigiCert TLS ECC P384 Root G5 (until 2046), the cross-certificate of the same name issued by DigiCert Global Root G3 (until 2036), and the self-signed Global Root G3. `ti pki verify --connect` draws them as one line of descent:

```
✓ dienst.vsdd2.ru.service-ti.de
└── ✓ GeoTrust G5 TLS ECC P-384 SHA384 2022 CA2
    └── ✓ DigiCert TLS ECC P384 Root G5           CA · until 2046-01-15
        └── ✓ DigiCert TLS ECC P384 Root G5       CA · until 2036-03-31
            └── ✓ DigiCert Global Root G3
```

A self-signed certificate is a trust anchor, and a path ends there (RFC 5280 §6.1). Shown under it, the cross-certificate looks like the issuer of the root. It has the same name and key, so a signature check does not tell them apart. The view should show the path that was verified, ending at the anchor it ended at, and list what the server sent beyond that apart.

Not checked: whether the verdict's path (rustls-webpki) ended at Root G5 or at Global Root G3, and which part of the CLI builds the view, the verified path or the certificates as sent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The chain view shows the verified path, ending at its trust anchor, and lists the certificates the server sent outside that path separately
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
ti-tls's WebCheck::verify returns the path rustls-webpki verified on the verdict (Verdict::path: end entity, CAs, the root certificate of the trust anchor it ended at). ti-cli's web report draws that path, the anchor marked as in the trust store, lists the certificates the server sent outside it in a section of their own (issuer named, so a cross-certificate shows as issued by the other root), and adds the path to the JSON (path, positions end_entity/sub_ca/trust_anchor). Without a path (refused before one was built) the view stays the chain as sent.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: the same connection fails in the zeta CLI. ZETA SDK 2.0.1 checks the revocation of the chain as sent, and stops at the self-signed Root G5 the server sends. That is in zeta-backlog TASK-19.

2026-11-22: The view came from verify_tls_server.rs tree(): super::chain_tree over the certificates as sent (TlsServerVerdict::chain), not over a verified path; the verdict exposed no path. rustls-webpki looks for a trust anchor before the intermediates at every step, so with Root G5 in the store the path ends at Root G5; checked live 2026-11-23 against dienst.vsdd2.ru.service-ti.de: path leaf -> GeoTrust G5 CA2 -> DigiCert TLS ECC P384 Root G5 (trust anchor); the server now sends four certificates (no Global Root G3), the cross-certificate from Global Root G3 is listed outside the path. The TI path of pki verify already drew ti-pki's validated chain, unchanged. Test dev-deps added to ti-cli (x509-cert builder, der, p256, getrandom): all already in the workspace and lock file through ti-hsm-proxy's tests, no new crate.

Verification: ti-cli/ti-client/ti-tls nextest 346/346 (all features), clippy both feature sets and rustdoc clean, traceability re-blessed. just check-changed (8 crates): everything passes except ti-cli::probe probes_protocols_catalog_instances_and_timeouts, which fails only under the full parallel load (5.1 s against 4.1 s alone) and passes alone and with the three touched crates; it failed the same way on the TASK-391 run, so it is timing, not this change.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
`ti pki verify --connect` under the web profile now draws the path the verdict was judged on, ending at its trust anchor (RFC 5280 6.1), marked 'trust anchor, in the trust store', and lists the certificates the server sent outside that path in a section 'Sent, outside the path', each with its issuer, so a cross-certificate reads 'issued by <other root>'. ti_tls::Verdict carries the verified path (Verdict::path: end entity, CAs, the anchor's root certificate) from WebCheck::verify; the JSON gains `path` (end_entity / sub_ca / trust_anchor), schema updated. Without a path (refused before one was built) the view is the chain as sent, as before. Live check against dienst.vsdd2.ru.service-ti.de: the path ends at DigiCert TLS ECC P384 Root G5, the cross-certificate from Global Root G3 is listed outside. Test: ti-cli rfc_5280_6_1_the_chain_view_ends_at_the_trust_anchor (generated leaf, intermediate, self-signed R1, cross-certificate R1 by R2, self-signed R2; R1 the anchor).
<!-- SECTION:FINAL_SUMMARY:END -->
