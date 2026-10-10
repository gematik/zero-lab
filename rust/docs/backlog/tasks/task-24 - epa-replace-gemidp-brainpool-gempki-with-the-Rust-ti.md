---
id: TASK-24
title: 'epa: replace gemidp, brainpool, gempki with the Rust ti'
status: In Progress
assignee: []
created_date: '2026-10-10 15:04'
updated_date: '2026-10-10 16:10'
labels:
  - epa
  - ti-cli
  - ti-idpd
dependencies: []
priority: high
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/epa loses its dependencies on gemidp, brainpool/josebp, gempki (and with them pkcs12 and the openssl subprocess) and gets that functionality from the Rust ti as a subprocess behind Go interfaces (Identity, Authenticator, CertVerifier). Stages: (1) ti identity inspect|sign with P12/PEM/Konnektor identities, --p12-password-path, ti pki verify-signature, RU CertData autodetection fixture in ti-pki; (2) crate ti-idpd (IDP-Dienst Authenticator-Modul as sans-I/O engine + ureq adapter) and ti idpd authenticate; (3) go/epa/ti runner, SecurityFunctions -> Identity.SignJWT, raw-DER vau.CertData with real VAU chain + host-key verification (warn|enforce), authn_connector config, go.mod drops the four modules, Dockerfile gets a Rust stage for ti; (4) docs and release notes. Design and rationale: docs/backlog/docs/doc-1.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 cd rust && just check passes incl. ti-idpd on wasm32; ti schema identity sign|idpd authenticate|pki verify-signature print valid schemas
- [ ] #2 a JWS signed by ti identity sign verifies in go/brainpool/josebp (interop vector in jwz-brainpool/interop); the same with --connector against a Konnektor and a real SMC-B (HITL)
- [ ] #3 ti idpd authenticate against the RU IDP with the test SMC-B returns a code (HITL)
- [ ] #4 go list -deps ./epa/... shows no gemidp, brainpool, gempki, pkcs12; grep for brainpool|gemidp|gempki|pkcs12|openssl in go/epa is empty; go test ./epa/... passes with the fake runner without ti installed
- [ ] #5 HITL on RU: just epa-connect-test, just epa-entitle-test, zero-epa probe patient (P12 and authn_connector), zero-epa proxy /info shows the admission statement, VAU verdicts logged in warn mode, Docker image runs probe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Stage 1 (Rust) implemented on feat/epa-rust-ti: ti identity inspect|sign (P12, PEM, Konnektor sources; AUT selection; ES256 on brainpoolP256r1 via jwz-brainpool or P-256 via jwz), ti pki verify-signature (DER or raw, ti-pki verifiers), --p12-password-path / TI_P12_PASSWORD_PATH on pki inspect, pki verify and identity; schemas identity-inspect, identity-sign, pki-verify-signature; TEST-ONLY identity fixtures in ti-cli/tests/fixtures/identity (generate.sh, PROVENANCE.md); tests in ti-cli/tests/identity.rs and schema.rs. Deferred from stage 1: the josebp interop vector goes into the Go epa tests of stage 3 (the real consumer; the signature math is jwz-brainpool's, already in the interop corpus); the RU CertData fixture + epa-vau-aut autodetection test needs a recorded CertData from RU (take it from a zero-epa debug run, stage 3). HITL still open: identity sign --connector with a real SMC-B.

HITL 2026-10-10 (user): identity inspect/sign with the gematik test SMC-B P12 and with SMC-B-7 at the Konnektor (selected .kon, PIN.SMC verified) — AUT selected, Telematik-ID shown, ES256 JWS with x5c; the card-signed JWS verified with the card's C.AUT via pki verify-signature (raw r‖s). --card alone now resolves the Konnektor like the connector commands.
<!-- SECTION:NOTES:END -->
