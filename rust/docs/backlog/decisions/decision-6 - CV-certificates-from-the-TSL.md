---
id: decision-6
title: CV certificates from the TSL
date: '2026-10-12 18:00'
status: proposed
---
## Context

The TSL lists the CVC root CA certificates and the cross CV certificates between root generations next to the X.509 CAs (gemSpec_TSL 1.25.0):

- TIP1-A_5963: `ServiceTypeIdentifier` is the URI TIP1-A_4099-01 names for them; the TSLs carry `http://uri.telematik/TrstSvc/Svctype/CA/CVC`.
- TIP1-A_5964: `ServiceName/Name` is `CHR={CHR}, CAR={CAR}`, 11 characters each; CHR equal to CAR marks a root certificate.
- TIP1-A_5965, TIP1-A_4104: `DigitalId` holds an `Other` element with a `CVCertificate` (namespace `http://uri.etsi.org/02231/v2#`), the base64 CV certificate. `Other` also carries DNSSEC trust anchors.
- TIP1-A_5967: an extension `oid_cv_rootcert` (`1.2.276.0.76.4.185`) for a root, `oid_cv_cert` (`1.2.276.0.76.4.186`) for a cross certificate; ti-pki already names both (`oid::CV_ROOTCERT`, `oid::CV_CERT`).

ti-pki parses these services but drops their certificate: `DigitalId` reads only `X509Certificate`, so a CA/CVC service comes out with `certificate: None` and nothing else. The real test TSL `spec/tsl-xmldsig/testdata/tsl/real/tu-10713.xml` has 13 of them: the roots of generations 85 to 89 and cross certificates in both directions, among them `CHR=DEGXX870222, CAR=DEGXX860220`.

The consumer is kartos, the TI card simulator. Its cards verify CV certificate chains themselves (gemSpec_COS PSO VERIFY CERTIFICATE) and need the CVC root public keys as trust anchors and the cross certificates to bridge root generations: a card-to-card authentication between an eGK under root 86 and an HBA under root 87 fails without the 87-signed-by-86 cross certificate, which a Konnektor takes from the TSL. kartos reads the CVCs today with a TSL parser of its own (`kartos-tsl`) that does not check the signature. It wants to take them only from a TSL ti-pki verified (`Tsl::parse_verified_auto`) and drop its parser.

## Decision (proposed)

1. `tsl::Service` gains `cv_certificate: Option<Vec<u8>>`, the base64-decoded content of `DigitalId/Other/CVCertificate` exactly as published (a complete CV certificate, tag `7F21`). A CA/CVC service has it and `certificate: None`; an X.509 service the other way round. Other content of `Other`, such as DNSSEC trust anchors, stays ignored.
2. A constant `SERVICE_TYPE_CA_CVC = "http://uri.telematik/TrstSvc/Svctype/CA/CVC"`, next to `SERVICE_TYPE_CA_PKC`.
3. `Tsl::cv_certificates(&self) -> Vec<CvCertificate>` for the services in accord, in document order:
   - `chr: String`, `car: String` from the `Name` (TIP1-A_5964);
   - `kind: CvKind` (`Root`, `Cross`) from the extension OID (TIP1-A_5967);
   - `certificate: Vec<u8>`, the bytes of point 1.
   ti-pki does not parse the CV certificate's body, check its chain or decide trust; the bytes go to the consumer, which has a COS to do that.
4. A CA/CVC entry that breaks the rules above (no `CVCertificate`, base64 that does not decode, a `Name` not of the form `CHR=…, CAR=…`, CHR equal to CAR under `oid_cv_cert` or unequal under `oid_cv_rootcert`) is handled like any other broken entry: it rejects the list, or lands in `skipped` where parsing skips.
5. The same on `Tsl::parse` and on `parse_verified*`; extracting the bytes needs no crypto, so it also works with `default-features = false`.

## Consequences

- kartos raises its ti-pki pin, turns on `brainpool` (the TSL signers' keys) and, for the test and reference TSLs, `dangerous-nonprod`, verifies every TSL with `parse_verified_auto`, takes `Root` entries as card trust anchors and offers `Cross` entries for card-to-card authentication across root generations. `kartos-tsl` is deleted (kartos backlog task-11, task-22, task-21).
- Tests in ti-pki on `tu-10713.xml`: 13 CV certificates; the root `DEGXX870222` and the cross certificate `CHR=DEGXX870222, CAR=DEGXX860220` present, each starting with `7F21`; `kind` agrees with CHR and CAR; a broken entry per rule of point 4.
- Optional, not needed by kartos: `tsl show` and ti-report list the CV certificates with CHR, CAR and kind.
- No change to X.509 path validation. Checking the root key fingerprint (TIP1-A_5990) is the TSL service's duty before publishing, not the consumer's.

## Open questions

- Field and type names: `cv_certificate` and `CvCertificate`, or `cvc` and `CvcEntry`, in line with decision-5.
- Whether `cv_certificates()` should also return entries not in accord, marked, for a consumer that shows the whole list.
