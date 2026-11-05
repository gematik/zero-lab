# Real TI material

Certificates, OCSP responses and a TSL as gematik's PKI issued them: the reference and test
environments' TEST-ONLY material and some production material, all public. Nothing here is
generated; the generated test PKI is in [`../pki`](../pki/PROVENANCE.md). Tests pin times,
serials and names of these files, so a file is never replaced in place: a newer capture is
a new file and the tests that use it change with it.

| File | What | Source | Added |
| --- | --- | --- | --- |
| `admission-1.pem`, `smcb-ee-test-only.pem` | the C.HCI.AUT of a TEST-ONLY SMC-B (Arztpraxis Bernd Rosenstrauch) under GEM.SMCB-CA51 TEST-ONLY | added with the port of `go/gempki` (archived at `go/gempki/v0.23.1`); the original source is unknown | `7d5c2863`, 2026-09-23 |
| `admission-2.pem` | a TEST-ONLY SMC-B certificate (Adler Apotheke) | as above | `7d5c2863` |
| `rca5-test-only.pem` | GEM.RCA5 TEST-ONLY, the reference environment's brainpool root | as above | `7d5c2863` |
| `rca2-rsa-test-only.pem` | GEM.RCA2 TEST-ONLY, an RSA root | as above | `7d5c2863` |
| `smcb-ca51-test-only.pem` | GEM.SMCB-CA51 TEST-ONLY under GEM.RCA5 TEST-ONLY | as above | `7d5c2863` |
| `ocsp-smcb-ca51-test-only.der`, `ocsp-smcb-ca51-test-only-sha1.der` | live answers of the reference environment's root responder about GEM.SMCB-CA51 TEST-ONLY (SHA-256 and SHA-1 CertID), producedAt 2026-09-23T18:44:38Z | recorded from the responder named in the CA certificate; the exact request is not recorded | `1d3cae25`, 2026-09-23 |
| `tsl-signing-unit-6.pem` | TSL Signing Unit 6, the production TSL signer under GEM.TSL-CA3 | not recorded; it is the signer of the production TSLs of that time | `302cf8e5`, 2026-10-03 |
| `tsl-signing-unit-12-test-only.pem` | TSL Signing Unit 12 TEST-ONLY under GEM.TSL-CA28 TEST-ONLY | not recorded; it is the signer of the test environment TSLs of that time | `69d6cd2c`, 2026-10-03 |
| `ocsp-tsl-signing-unit-6.der`, `ocsp-tsl-signing-unit-12-test-only.der` | live answers of the TSL OCSP responders about those two signers, producedAt 2026-10-03T18:10:21Z | recorded from the responders in the signers' AuthorityInfoAccess | `69d6cd2c` |
| `tsl-ca-ocsp-signer-10-test-only.pem` | TSL-CA OCSP-Signer10 TEST-ONLY under GEM.TSL-CA28 TEST-ONLY | taken from a recorded OCSP response or a test environment TSL; which one is not recorded | `6edadaea`, 2026-11-02 |
| `tsl/ECC-RSA_TSL.xml` | the production TSL(ECC-RSA), TSLSequenceNumber 10333, ListIssueDateTime 2026-09-13T23:00:08Z, unmodified | the production download point; the URL used is not recorded (`ti_pki::tsl::URL_PROD` is `https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml`) | `472fe95a`, 2026-09-23 |

The published TSLs with their detached signatures and `.ocsp` files, captured together,
are in [`spec/tsl-detached/testdata`](../../../../spec/tsl-detached/testdata/README.md).

## Refresh

None of these is refreshed automatically. To add a newer capture:

- certificates: from a current TSL of the environment or a test card, as PEM, named
  after the certificate and its environment;
- OCSP responses: ask the responder in the certificate's AuthorityInfoAccess with the
  request `ti_pki::ocsp::request` builds, store the DER response, and pin its producedAt in
  the test that uses it;
- the TSL: download it from the environment's download point (`ti_pki::tsl::URL_PROD` and
  its siblings) unmodified, then run `cargo test -p ti-pki --all-features`; the corpora
  under `spec/pki-path/testdata` that read these files (`ocsp.json`, `validate.json`) are
  rewritten with `TI_PKI_BLESS=1` and must then pass in `go/tipki` too.
