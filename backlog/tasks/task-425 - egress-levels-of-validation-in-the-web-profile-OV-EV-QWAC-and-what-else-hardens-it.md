---
id: TASK-425
title: >-
  egress: levels of validation in the web profile (OV, EV, QWAC) and what else
  hardens it
status: To Do
assignee: []
created_date: '2026-11-25T17:36:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 438000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up of TASK-408 AC 3: the hardening of the web profile researched on 2026-11-25, with sources. Today the web profile (spec/pki-validation, go/egress) checks the path to the system's roots, keys, name, validity period and revocation, and knows one level: any certificate of the Web-PKI.

What asks for more. gemSpec_Krypt V2.51.0, 3.17.1, A_28933: before using the BfArM web service the E-Rezept- and TI-Flow-Fachdienst check that the server certificate's certificatePolicies hold 2.23.140.1.2.2 (OV) or 2.23.140.1.1 (EV) and abort otherwise. Beside it A_27855-03 (path to a CA under the CA/B Forum Baseline Requirements), A_27856-02 (name), A_27857-02 (revocation; abort when it cannot be checked; the profile deviates today with a warning), A_29774 to A_29776 (TLS 1.2 and 1.3 as a client, suites, TR-02102-2 parameters). https://gemspec.gematik.de/downloads/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.51.0.html

Levels and how a client tells them. The CA/B Forum's reserved policy identifiers: 2.23.140.1.2.1 domain validated (no identity asserted), 2.23.140.1.2.2 organization validated, 2.23.140.1.2.3 individual validated, 2.23.140.1.1 extended validation (object registry https://cabforum.org/resources/object-registry, Baseline Requirements https://cabforum.org/working-groups/server/baseline-requirements/requirements/). An EV certificate also carries subject fields a client can require: businessCategory, serialNumber (the registration number), jurisdictionCountryName 1.3.6.1.4.1.311.60.2.1.3 (EV Guidelines https://cabforum.org/working-groups/server/extended-validation/guidelines/). A policy identifier in the leaf proves little alone: the chain's CAs must be allowed to assert it (policy constraints, RFC 5280 6.1), and for EV the root programs keep a list of roots enabled for EV with their policy OIDs, which the system's root store does not expose to Go; to be decided where such a list comes from. Qualified website certificates (eIDAS): policies 0.4.0.194112.1.4 (named QCP-w or QEVCP-w by different sources) and 0.4.0.194112.1.5 (QNCP-w) of ETSI EN 319 411-2, and the qcStatement id-etsi-qct-web 0.4.0.1862.1.6.3 of ETSI EN 319 412-5; trust comes from the EU trusted lists, not the web roots; 2-QWACs in ETSI TS 119 411-5 (as Chromium and Firefox read them: https://sources.debian.org/src/chromium/139.0.7258.127-1/net/cert/qwac.h, Entrust's policy https://www.entrust.com/sites/default/files/documentation/licensingandagreements/ecs/entrust-eu-cp-for-eidas-qwac-v1-5.pdf). The OID names differ between sources and are to be read from the ETSI texts before they are written into the specification.

What else hardens, and what changed under the profile. Validity: the Baseline Requirements cut a certificate's life to 200 days from 2026-03-15, 100 from 2027-03-15 and 47 from 2029-03-15 (ballot SC-081v3, https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/); the profile's MaxValidity is to follow by date. Revocation: OCSP has been optional for public CAs since 2023, and Let's Encrypt removed OCSP URLs from certificates on 2025-05-07 and shut its responders on 2025-08-06 (https://letsencrypt.org/2024/12/05/ending-ocsp/, https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life); CRLs are what remains, so a strict A_27857-02 rests on the CRL path, and short-lived certificates carry no revocation information at all. Certificate Transparency: Chrome requires SCTs from 2 logs for certificates of at most 180 days and 3 above, from two log operators (https://googlechrome.github.io/CertificateTransparency/ct_policy.html); a client that requires SCTs needs the list of logs and its updates, which is a dependency and a feed to evaluate; spec/pki-validation names CT as not covered. Not researched here and open: pinning of an issuer or key per endpoint, CAA (the issuer's duty, not a client's check), DANE.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/pki-validation states the levels of the web profile (any, OV or EV, EV, and whether QWAC) with the checks of each, read from the CA/B Forum and ETSI texts, and conformance cases for them
- [ ] #2 go/egress lets the host choose the level per endpoint; A_28933 is met by the OV-or-EV level, with tests named after it
- [ ] #3 It is decided and recorded which roots may assert EV and where that list comes from, or that the EV level is not offered
- [ ] #4 The validity limit follows the Baseline Requirements' schedule by date
- [ ] #5 A strict mode refuses when revocation cannot be checked (A_27857-02) and its behaviour for certificates without revocation information is specified
- [ ] #6 Certificate Transparency, pinning and DANE are each decided: adopted with a task, or recorded as not covered with the reason
<!-- AC:END -->
