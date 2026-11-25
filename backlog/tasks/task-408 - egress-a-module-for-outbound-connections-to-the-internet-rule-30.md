---
id: TASK-408
title: 'egress: a module for outbound connections to the internet (rule 30)'
status: Done
assignee: []
created_date: 2026-11-22 12:47
updated_date: '2026-11-25T17:37:00Z'
labels:
  - go
  - security
  - servers
dependencies: []
references:
  - docs/design/servers.md
priority: medium
ordinal: 421000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
tipki is the TI's private PKI; outbound connections of TI 2.0 go mostly to the internet, with hardening of their own and profiles up to EV certificates (maintainer, 2026-11-22). The web profile of spec/pki-validation lives in tipki/titls today (web.go, WebVerifier, NewWebHTTPClient) and takes OCSP from tipki. go/egress takes it over: its own handshake constants (not shared with titls, as the profiles will diverge), the web profile's verification with OCSP through golang.org/x/crypto/ocsp (approved 2026-11-22; internet CAs are RSA and NIST curves only) and CRLs through crypto/x509, a Fetcher interface the host fills (titls.HTTPFetcher satisfies it), and the egress client of servers.md rule 30: https only, plain http only for a request marked SelfVerifying (OCSP, CRLs, the TSL of A_21175), the rule in the transport's Proxy hook so that clones keep it. No dependency on tipki. titls becomes TI only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 go/egress is a module of its own in go.work, without a dependency on tipki, with its own handshake constants, the web profile's checks and tests (TLSV-04x and TLSV-05x cases of the web profile), and the egress client of rule 30 with tests named after it
- [x] #2 zero-pep-proxy, zero-epa, idpd and their tests take the egress client from go/egress; titls keeps no web profile
- [x] #3 Hardening profiles up to EV certificates are researched and written down as a follow-up task with sources
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: go/egress built (6cf9e1dd) and the consumers switched (180d024d), on feat/pep-listen-url-egress. API: NewClient(timeout, Options) (egress client, https only, plain http only for SelfVerifying requests, rule in the Proxy hook), NewTransport(Options) (peers, no rule, no proxy), SelfVerifying(ctx), ErrPlainHTTP, WebCheck/NewWebCheck/SystemWebCheck, WebVerifier/NewWebVerifier/ClientConfig, Verdict/Code/RefusedError, Fetcher/Offline/HTTPFetcher, MaxValidity, MaxStatusReuse, DefaultCacheSize. tipki/fetch.WithSelfVerifying, titls.HTTPFetcher.Mark and idpd.WithSelfVerifying / ClientConfig.MarkSelfVerifying take the marking as a func, so neither module imports the other. OCSP through x/crypto/ocsp; checked here: issuer or a delegate it certified directly with id-kp-OCSPSigning, valid now (±37.5 s); signature algorithm on the web list (no SHA-1); thisUpdate <= now <= nextUpdate; a present certHash names the leaf. Differences from tipki's path: x/crypto takes the first embedded certificate as the responder, not the one the ResponderID names, and matches the single response by serial only, not by the CertID's issuer hashes (the signature by the issuer or its delegate binds it to the issuer). All 32 web corpus cases pass, fuzz 30 s clean. Not yet: consumer go.mod requires of go/egress (a placeholder require breaks the workspace build, so none is added; before just sync: go mod edit -require=github.com/gematik/zero-lab/go/egress@v0.0.0 in idpd, epa, pep/proxy, pdp, then just sync); AC #3.

2026-11-22, maintainer: AC #3 (hardening research) later.

2026-11-25: AC 3: the hardening researched and written down as TASK-425 with its sources. What asks for levels is gemSpec_Krypt V2.51.0 A_28933 (OV or EV by policy identifier for the BfArM web service); beside it the Baseline Requirements' validity schedule (SC-081v3), the end of OCSP at public CAs, Certificate Transparency and qualified website certificates.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/egress is the module for a server's connections to the internet: the web profile of spec/pki-validation with its own handshake constants, OCSP and CRL checks, and the egress client of servers.md rule 30; zero-pep-proxy, zero-epa and idpd take it from there, and titls is TI only. The hardening beyond it (levels up to EV and QWAC, validity schedule, strict revocation, Certificate Transparency) is researched with sources in TASK-425.
<!-- SECTION:FINAL_SUMMARY:END -->
