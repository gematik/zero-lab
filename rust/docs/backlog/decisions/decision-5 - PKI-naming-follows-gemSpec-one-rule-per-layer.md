---
id: decision-5
title: PKI naming follows gemSpec, one rule per layer
date: '2026-10-11 10:04'
status: accepted
---
## Context

gemSpec names the same things in several ways: certificate types by holder in Tab_PKI_405 (`C.HCI.AUT`), their OIDs by card in gemSpec_OID (`oid_smc_b_aut`), technical roles by service (`oid_idpd`), cards by product (SM-B, eGK, HBA; at the Konnektor `SMC-B`, `EGK`, `HBA` and `C.AUT`). The project mixed them: profiles `smb-aut` (an invented "SMB") and `idp-sig` (role `oid_idpd`), institution constants that matched neither their reference nor the type names, `--profile` exact while `--issues` folded, ehca-go with card-based keys (`egk-aut`, `smcb-aut-arzt`). Nothing had been released to users that depends on the names (2026-10-11), so renames need no deprecation.

## Decision

1. Shown and JSON certificate type values are the Tab_PKI_405 names verbatim (`C.FD.TLS-S`, `C.NK.VPN`), also for types ti-pki does not validate; an OID the table does not name stays dotted.
2. OID constants are the gemSpec_OID reference name without `oid_`, uppercased, `-` as `_`, prefixed by their table (`CERT_TYPE_`, `TECH_ROLE_`, `INST_`, `PROF_`, `POLICY_`, `CV_`); a leading word that repeats the table (`policy_`, `cv_`, `institution-`) is dropped, `bs_` (Betriebsstätte) is kept: `INST_PRAXIS_ARZT`, `INST_BS_GEMATIK`, `CERT_TYPE_SMC_B_AUT`.
3. Type enums follow Tab_PKI_405 (`CertificateType::HciAut`).
4. Profile names are kebab-case: bound to one type, the type name without `C.` (`hci-aut`, `fd-tls-s`, `tsl-sig`); bound to a technical role, the role reference without `oid_` plus the usage (`idpd-sig`, `epa-vau-aut`, `zeta-guard-aut`).
5. One input rule for type and profile names, `ti_pki::cert_type::fold_name`: case ignored, `.` and `-` alike, a leading `C.` dropped; `--profile`, `profiles describe` and `--issues` use it, the output is always the canonical name.
6. JSON: `certificate_type` for one value, a `…_types` field for a list (`accepts_types`, `issuable_types`); the `cert_type_*` error codes stay as they are.
7. Card names (`EGK`, `HBA`, `SMC-B`, `C.AUT`) only where a card is meant (`connector`, `identity`); "SM-B (SMC-B, HSM-B)" where both are meant. Card to holder to type: eGK is CH, HBA is HP, SM-B is HCI.

## Consequences

- Renamed without aliases: profiles `smb-aut` to `hci-aut`, `idp-sig` to `idpd-sig` (ti-pki statics `HCI_AUT`, `IDPD_SIG`); 24 `INST_*` constants and `CERT_TYPE_CM_TLSCS` to `CERT_TYPE_CM_TLS_C` (gemSpec_OID's reference for C.CM.TLS-CS); the `tsl show` field `issues` to `issuable_types`; the IDP signer fixtures to `idpd-sig.*`.
- Go `gempki` (frozen) keeps its names (`CertTypeSmcBAUT`); zero-epa's camelCase `/info` JSON (`professionItems`) is a public API and changes only with its next breaking release.
- Proposed to ehca-go, not decided here: keys derived the same way (`ch-aut`, `hci-aut-praxis-arzt`) or at least `certificate_type` in its output; sector keys from the Tab_PKI_403 references.
