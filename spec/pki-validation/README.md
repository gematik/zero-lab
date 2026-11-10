# TLS server certificates

Language-neutral rules for a TLS client's verification of the server it connects to, under one of two
profiles: `ti` for endpoints of the Telematikinfrastruktur, whose trust is the TI's own, and `web` for
endpoints on the internet, whose trust is the host system's root store. The TI's PKI implements `ti`
(`rust/ti-pki`, `go/tipki`); the TLS layer implements `web` and the handshake rules, and hands `ti` to the
TI's PKI (`rust/ti-tls`, and its Go counterpart). [`testdata`](testdata) holds them together.

Each rule has one identifier, and tests cite them. MUST and MUST NOT are used as in RFC 2119.

## Scope

In scope: the TLS versions, cipher suites, groups and handshake signatures a client offers and accepts, and
the verification of the server's certificate chain, name and revocation status, before any application data
is sent.

Not in scope: client certificates (mutual TLS), the Konnektor, whose trust is the pinning of its `.kon` file,
the inner channels of the VAU and ZETA/ASL, Certificate Transparency, and the server side.

## References

- gemSpec_PKI V2.28.0: GS-A_4662, GS-A_4663 with Tab_PKI_273, GS-A_5077, TUC_PKI_018, TUC_PKI_006, GS-A_5336,
  Tab_PKI_247 (C.ZD.TLS-S), Tab_PKI_250 (C.FD.TLS-S)
- gemSpec_Krypt V2.51.0: GS-A_4384-03, GS-A_4385, A_18467, A_18464, GS-A_4387, GS-A_5035, A_21275-01,
  GS-A_5542, GS-A_5322, A_24913, A_28976, A_16176-01, A_27855-03, A_27856-02, A_27857-02, A_29774, A_29775,
  A_29776
- gemSpec_OID V3.26.0: Tab_PKI_405
- RFC 5280 (paths, CRLs), RFC 6960 (OCSP), RFC 6066 §8 (stapling), RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2),
  RFC 5746 (renegotiation), RFC 8734 (brainpool in TLS 1.3), RFC 9525 (service identity)
- BSI TR-02102-2, the 120-bit level of gemSpec_Krypt §4
- gematik's ZETA SDK (`github.com/gematik/zeta-sdk`, `network/.../config/tls`), which states the internet
  rules for ZETA clients
- [`spec/pki-path`](../pki-path/README.md) for chains, roots, OCSP and the verdict in the TI

## Profiles

Being a TI service does not decide the profile; the certificate a service presents does. The ePA
Aktensysteme and KIM present TI certificates and take `ti`. The IDP-Dienst, the E-Rezept, the
FHIR-Directory and the TSL download points are reached over the internet with public certificates and
take `web`.

- **`ti`**: a server of the TI, whose certificate is a C.FD.TLS-S or C.ZD.TLS-S of the TI's component PKI.
  Trust is the TI's alone: the roots walked from the compiled-in anchor and the CAs of the verified TSL, as
  [`spec/pki-path`](../pki-path/README.md) builds them. No public root takes part.
- **`web`**: a server on the internet, such as an OpenID Federation master or provider, or gematik's
  development gateways. Trust is the host system's default root store, the one its TLS stack and Go's
  standard library use (in a container, the distribution's `ca-certificates` bundle). No list of roots is
  kept here: the rules below add requirements on top of the Web-PKI, they do not curate it.

## Rules

### Selection

- **TLSV-001** The profile is the endpoint's, by configuration, before the connection is made. It is never
  inferred from what the server presents. Neither profile falls back to the other, nor `ti` to any public
  root. An endpoint without a profile is not connected to.
- **TLSV-002** No application data is sent before the verdict is valid (GS-A_4662). A refused server ends
  the handshake with a fatal alert (GS-A_5542). A verifier cannot be configured to skip a rule; what is
  configured is the trust material, the OCSP grace period and the clock.

### Handshake

- **TLSV-010** TLS 1.2 and TLS 1.3 only (GS-A_4385, A_18467, A_29774). TLS 1.1, 1.0 and SSL are refused
  (A_18464, GS-A_4387, GS-A_5035).
- **TLSV-011** In TLS 1.3 the cipher suites `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`; in TLS 1.2
  only ECDHE with AES-GCM: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `…_AES_256_GCM_SHA384` and their
  `ECDHE_RSA` counterparts (GS-A_4384-03, A_29775, A_29776). Nothing else is offered or accepted.
- **TLSV-012** Key exchange on P-256 and P-384, and on brainpoolP256r1 and brainpoolP384r1 where the TLS
  library has them (GS-A_4384-03: other curves MUST NOT be used). X25519 and hybrid groups are not offered.
- **TLSV-013** Handshake signatures hash with SHA-256, SHA-384 or SHA-512 only (A_21275-01): ECDSA on P-256
  with SHA-256 and on P-384 with SHA-384, ECDSA on brainpoolP256r1 and brainpoolP384r1 (RFC 8734) under
  `ti`, RSA-PSS, and RSA PKCS#1 v1.5 in TLS 1.2 only. SHA-1, SHA-224 and EdDSA are not offered.
- **TLSV-014** Renegotiation only as RFC 5746 has it. Key material of a resumed session is at most 24 hours
  old (GS-A_5322).

### Every profile

- **TLSV-020** A path is built from the server's end-entity certificate, the first it sends, to an anchor
  of the profile, through the other certificates it sent and, under `ti`, the CAs of the trust material.
  Certificates the path does not need are ignored. A path that cannot be built is `chain_incomplete`,
  whatever its links are signed with: the path is judged before TLSV-021 to 023 judge its certificates.
- **TLSV-021** The end entity and every CA of the path are valid at the reference time, the clock's (TUC_PKI_002),
  or the result is `not_yet_valid` or `expired`.
- **TLSV-022** The end entity's extended key usage contains `id-kp-serverAuth`, and its key usage, where
  present, `digitalSignature` (`key_usage_mismatch`).
- **TLSV-023** No certificate of the path below the anchor is signed with SHA-1, MD5 or SHA-224
  (`signature_algorithm_not_allowed`), and each signature verifies (`signature_invalid`). Under `web`, a
  weakly signed certificate whose issuer the server did not send may also be `chain_incomplete`: a host
  store that refuses the weak signature itself need not say whether that issuer is one of its anchors.
  Either way the server is refused.
- **TLSV-024** The reference identity is the host name the client connected to, never one the server
  supplied, in its ASCII form (an internationalized name as its A-labels). It is compared
  case-insensitively, without a trailing dot (RFC 9525 §6.3). A presented name may be a wildcard: `*` as
  the whole leftmost label, standing for exactly one label of the reference name, never for a dot, never
  for a partial label (`f*.example.com`), and never matching a name with fewer labels than its own
  (`*.example.com` does not match `example.com`). A wildcard in any other position matches nothing. An IP
  address matches only an `iPAddress` subject alternative name of the same bytes. A mismatch is
  `name_mismatch`.

### Profile `ti`

- **TLSV-030** The end entity is checked by TUC_PKI_018 with the parameters of Tab_PKI_273 (GS-A_4663): the
  path and verdict rules of [`spec/pki-path`](../pki-path/README.md) (PATH-001 to 007, VALID-001 to 007), the
  type among the TLS server types of Tab_PKI_405, C.FD.TLS-S and C.ZD.TLS-S (`profile_type_mismatch`), its
  baseline of Tab_PKI_250 and Tab_PKI_247, and its key under VALID-002.
- **TLSV-031** The reference host name MUST equal the commonName or one of the `dNSName` subject
  alternative names (GS-A_5077, Tab_PKI_247, Tab_PKI_250), as TLSV-024 compares them, wildcards included;
  a certificate may name a service under several names.
- **TLSV-032** Revocation is OCSP and cannot be switched off (Tab_PKI_273: Prüfmodus OCSP, no offline mode,
  TOLERATE_OCSP_FAILURE false). A stapled response (RFC 6066 §8) is used when it verifies under OCSP-001 and
  is within the OCSP grace period, 10 minutes by default and configurable (A_24913, TUC_PKI_018 7b).
  Otherwise the responder is asked under OCSP-001 to 005; a stapled response that did not verify is reported
  as the warning `provided_ocsp_response_not_valid` (TUC_PKI_018 7c). `revoked`, `unknown` and no answer
  refuse the server (`ocsp_revoked`, `ocsp_unknown`, `ocsp_unavailable`).
- **TLSV-033** Without a TSL within its grace period no TI server is accepted (GS-A_5336,
  `trust_material_unavailable`).

### Profile `web`

- **TLSV-040** The anchors are the host system's default root store as the host read it, and only those. A
  verifier adds none, removes none and keeps no list of its own. A test passes its own root in their place.
- **TLSV-041** The end entity's key is ECDSA on P-256 or P-384, or RSA of at least 3000 bits: the 120-bit
  level that gemSpec_Krypt requires of identities from an internet PKI (A_28976, after TR-02102-2) and of
  non-TI RSA keys (A_16176-01). An RSA key of 2048 to 2999 bits is accepted with the warning
  `key_phased_out`, the code VALID-002 gives the same key in the TI ([Deviations](#deviations)); a smaller
  RSA key and any other key are refused (`key_not_admissible`).
- **TLSV-042** A CA's key is ECDSA on P-256 or P-384, or RSA of at least 2048 bits
  (`key_not_admissible`). The lower RSA floor is the Web-PKI's today, as the ZETA SDK accepts it.
- **TLSV-043** The name matches a `dNSName` subject alternative name as TLSV-024 compares them
  (A_27856-02); the commonName is not read.
- **TLSV-044** The end entity's revocation status is required (A_27857-02): from a stapled OCSP response,
  else a cached response, else its OCSP responder (AIA), else its CRL (CRL distribution point), as the ZETA
  SDK asks them. `revoked` refuses (`revoked`); when no source gives a status, the server is accepted with
  the warning `revocation_unavailable` ([Deviations](#deviations)). An OCSP response counts when its issuer or a delegate it certified signed it
  and the reference time lies between `thisUpdate` and `nextUpdate`; a CRL counts when the issuer signed
  it, it is not past `nextUpdate`, and it covers the certificate's distribution point.
- **TLSV-045** The end entity's validity period is at most 398 days (`validity_too_long`), as the CA/Browser
  Forum's Baseline Requirements cap it.

### Reuse

- **TLSV-050** An accepted verdict may be reused for the same certificate bytes, host name and profile until
  the earliest of: the end entity's `notAfter`, the `nextUpdate` of the revocation status it rests on, and the
  replacement of the trust material it was reached with. A refusal is never reused, nor a verdict that rests
  on no revocation status (TLSV-044's `revocation_unavailable`): the next connection asks the sources again.
- **TLSV-051** A revocation status is reused within its `nextUpdate` and for at most the window the profile
  allows: under `ti` the OCSP-005 hour, under `web` 24 hours.

## Result codes

| Code | Rules |
|---|---|
| `valid` | – |
| `chain_incomplete` | TLSV-020, PATH-001, PATH-005 |
| `not_yet_valid`, `expired` | TLSV-021, PATH-002 |
| `key_usage_mismatch` | TLSV-022 |
| `signature_algorithm_not_allowed`, `signature_invalid` | TLSV-023, PATH-006 |
| `name_mismatch` | TLSV-024, TLSV-031, TLSV-043 |
| `profile_type_mismatch` | TLSV-030, VALID-005 |
| `key_not_admissible` | TLSV-030 (VALID-002), TLSV-041, TLSV-042 |
| `ocsp_revoked`, `ocsp_unknown`, `ocsp_unavailable`, `ocsp_response_invalid` | TLSV-032, OCSP-001 |
| `revoked` | TLSV-044 |
| `validity_too_long` | TLSV-045 |
| `trust_material_unavailable` | TLSV-033 |
| `ca_not_in_tsl`, `cert_type_ca_not_authorized`, `ca_revoked_in_tsl` | TLSV-030, VALID-006, VALID-007, VALID-003 |

Warnings never decide; a verdict carries them in the order of the steps below.

| Warning | Rules |
|---|---|
| `provided_ocsp_response_not_valid` | TLSV-032 |
| `key_phased_out` | TLSV-041 |
| `revocation_unavailable` | TLSV-044 |

## Algorithm

1. The profile is the endpoint's (TLSV-001); the handshake offers what TLSV-010 to 014 allow.
2. A reusable verdict is returned (TLSV-050).
3. The path (TLSV-020), validity (TLSV-021), usage (TLSV-022), signatures (TLSV-023).
4. The profile: `ti` TLSV-030, then the name (TLSV-031); `web` keys (TLSV-041, 042), the name (TLSV-043),
   the validity period (TLSV-045).
5. Revocation, only for a server that passed everything else (VALID-004): TLSV-032 or TLSV-044.

The first failing step's code is the result.

## Requirement mapping

| Requirement | Rules |
|---|---|
| GS-A_4662, GS-A_5542 | TLSV-002 |
| GS-A_4663, Tab_PKI_273, TUC_PKI_018 | TLSV-030, TLSV-032 |
| GS-A_5077 | TLSV-031 |
| GS-A_5336 | TLSV-033 |
| GS-A_4385, A_18467, A_18464, GS-A_4387, GS-A_5035, A_29774 | TLSV-010 |
| GS-A_4384-03, A_29775, A_29776 | TLSV-011, TLSV-012 |
| A_21275-01 | TLSV-013 |
| GS-A_5322 | TLSV-014 |
| A_24913 | TLSV-032 |
| A_27855-03 | TLSV-040 |
| A_28976, A_16176-01 | TLSV-041 (deviation) |
| A_27856-02 | TLSV-024, TLSV-043 |
| A_27857-02 | TLSV-044 (deviation) |

## Deviations

Two rules of the `web` profile accept, with a warning, what gemSpec_Krypt has a client refuse. Both are the
maintainer's decision of 2026-11-10 (TASK-282); the `ti` profile has neither.

- **A_28976, RSA below 3000 bits (TLSV-041).** gemSpec_Krypt asks for the 120-bit level of an identity from an
  internet PKI, RSA of 3000 bits or more. The Web-PKI's CAs issue RSA-2048 server certificates as their
  default, and services the TI's clients must reach present them. An end entity with RSA 2048 to 2999 bits
  is accepted with `key_phased_out`; below 2048 the key is still refused, and the CAs' floor (TLSV-042) is
  unchanged.
- **A_27857-02, revocation status required (TLSV-044).** A server whose status no source gives is accepted
  with `revocation_unavailable`. Let's Encrypt ended its OCSP service in 2025, and responders fail now and
  then: `idp-ref.app.ti-dienste.de` staples nothing and lists no CRL, so one failed answer from GlobalSign's
  responder made the IDP-Dienst unreachable. A status that says revoked still refuses, from any source, and
  a response that fails verification still counts as no status.

A host that needs the strict rules judges the server with the profile's verification entry point, which
returns the verdict with its warnings, and refuses a verdict that carries `key_phased_out` or
`revocation_unavailable` in its own verifier. The verifiers here do not offer it as an option.

## Security considerations

- `ti` trusts no public CA: a CA of the Web-PKI cannot vouch for a TI service, and a TI CA vouches only for
  the TI. `web` trusts what the host trusts; an operator who adds a root to the system adds it here.
- Revocation fails closed under `ti`: a TI server is unreachable while its revocation status is, by design.
  Under `web` it fails open with the warning `revocation_unavailable` ([Deviations](#deviations)): a revoked
  certificate is refused once any source says so, but an attacker who holds a revoked certificate's key and
  can block every source of its status is accepted. Such a verdict is not reused (TLSV-050).
- The name check uses the host the client asked for, so a server cannot name itself into a match. A
  wildcard covers one label under one domain: a certificate for `*.example.com` is good for every service
  directly under it, which its holder must want, and for nothing deeper or beside it.
- Reused verdicts end with the earliest reason to stop trusting them; a refusal is checked again every time.
- Not covered: a CA of the Web-PKI that issues wrongly and is not yet distrusted (Certificate Transparency
  would show it), and denial of service through unreachable OCSP responders or CRL hosts.
