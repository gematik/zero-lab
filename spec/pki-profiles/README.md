# Certificate types, admission and validation profiles

Language-neutral rules for what the Telematikinfrastruktur states in a certificate. `rust/ti-pki`
and `go/tipki` implement them, and [`testdata`](testdata) holds the two together. This covers only
reading a certificate's own content: a chain, the TSL and OCSP are not part of it, and a certificate
that passes these rules is not thereby trusted.

Each rule has one identifier `PROF-nnn`, and tests cite them. MUST and MUST NOT are used as in RFC 2119.

## Certificate types

- **PROF-001** A certificate's type is the first certificate policy that is a type OID of gemSpec_PKI
  Tab_PKI_405, or the policy of C.TSL.SIG. A type name compares with case ignored, `.` and `-` alike and
  a leading `C.` dropped.
- **PROF-002** Without such a policy, the type comes from the first admission OID naming a family, an
  institution (SMC-B), a profession (HBA) or the insurant (eGK), and the key usage: contentCommitment
  gives QES or OSIG, otherwise digitalSignature gives AUT, otherwise keyEncipherment or keyAgreement gives
  ENC. An eGK's AUT and ENC stay undetected, because their pseudonymous siblings look the same.

## Profiles

- **PROF-003** A profile with roles is selected only for a certificate asserting one. One such
  match wins, with reason `cert`. Several are `ambiguous`. Without one the profile owning the type
  by default wins, with reason `default`. Otherwise the only profile matching wins, with reason `cert`;
  several are `ambiguous`; none is `none`.

## Admission

- **PROF-010** An admission extension (1.3.36.8.3.3) is read as DER, wholly: a malformed later element
  refuses the whole. An extension with no admission or no profession info is refused. A
  profession item is a DirectoryString: valid UTF8String, PrintableString, ASCII TeletexString or UCS-2
  BMPString. A registration number is a PrintableString.
- **PROF-011** The result comes from the first profession info of the first admission.

## Requirements

- **PROF-020** Every requirement of a type is a floor, never an equality: all policies, all key usage bits,
  one extended key usage or anyExtendedKeyUsage, and one role. A profile's own roles replace the type's.
  The findings are `policy_mismatch`, `key_usage_mismatch` and `role_oid_missing`.

## Corpus

- **PROF-030** [`testdata/corpus.json`](testdata/corpus.json) holds the tables of types and profiles, and
  what each certificate of `rust/ti-pki/tests/pki/types` reads as. ti-pki writes it (`TI_PKI_BLESS=1`) and
  checks it, and `go/tipki` must read the same. [`testdata/admission.json`](testdata/admission.json) holds
  hand-built values, most of them malformed, on which both must agree. Where the two differ, the rule is
  settled here first.

- **PROF-031** The same corpus holds the table of gemSpec_OID identifiers with their reference names and
  descriptions, and the lists of professions and institutions, which both implementations MUST declare alike.

## Traceability

| Rule | Rust | Go |
|---|---|---|
| PROF-001, 002, 003, 020 | `prof_030_the_corpus_is_what_ti_pki_says` | `TestPROF030EveryCertificateReadsAsInTiPki` |
| PROF-010, 011 | `prof_010_admission_values_are_read_or_refused_as_stated` | `TestPROF010AdmissionValuesAreReadOrRefusedAsStated`, `FuzzParseAdmission` |
| PROF-030 | `prof_030_the_corpus_is_what_ti_pki_says` | `TestPROF030TheTablesAreThoseOfTiPki` |
| PROF-031 | `prof_030_the_corpus_is_what_ti_pki_says` | `TestPROF031TheIdentifiersAreThoseOfTiPki` |
