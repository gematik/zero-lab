# TSL signature verification: requirements and design

Language-neutral specification for authenticating the gematik Trust-service Status List
(TSL) and for the TSL update that depends on it. It is the binding basis for the Rust
implementation (`rust/ti-xmldsig`, `rust/ti-pki`) and for any later one (e.g. Go
`gempki`): an implementation built from this document alone, checked against the corpus
described in [CONFORMANCE.md](CONFORMANCE.md), is conformant.

Each rule has exactly one identifier `TSLSIG-nnn`. Tests cite these identifiers; the
gematik requirements map onto them in [Requirement mapping](#requirement-mapping). The
key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

- [Scope](#scope)
- [References](#references)
- [Signature profile](#signature-profile)
- [Rules](#rules)
  - [A. XML and signature](#a-xml-and-signature)
  - [B. Signer](#b-signer)
  - [C. Signer status](#c-signer-status)
  - [D. Update](#d-update)
  - [E. Trust anchor and anchor change](#e-trust-anchor-and-anchor-change)
  - [F. CA status](#f-ca-status)
  - [G. General](#g-general)
- [Result codes](#result-codes)
- [Algorithm](#algorithm)
- [Requirement mapping](#requirement-mapping)
- [Deviations](#deviations)
- [Security considerations](#security-considerations)

## Scope

In scope:
- the TSL(ECC-RSA) of the environments PU, RU and TU, fetched from the Internet download
  points of gemSpec_PKI 8.2.6 (A_30044);
- its enveloped XMLDSig/XAdES signature, the TSL signer certificate and its status;
- the TSL update: freshness, replay protection, grace period, trust anchor change;
- the use of the CA status (`ServiceStatus`, `StatusStartingTime`) in certificate checks.

Out of scope:
- XML Schema validation (TUC_PKI_020 step 3): a TSL with a valid gematik signature is
  taken as schema-conformant. `tsl_schema_not_valid` is never produced. Elements an
  implementation needs and cannot find make the affected entry unusable (TSLSIG-052), they
  do not fail the TSL;
- the TSL(RSA) (RSASSA-PSS, GS-A_5340/GS-A_5091); this profile rejects it;
- the detached signature `.sig` and the `.ocsp` file (A_21179 ff.);
- OCSP responders authorized by their TSL listing (A_30046 (7)); certificate-type
  extensions per CA (SE_1061); the BNetzA-VL and QES (A_30045, A_30047);
- the TI-1.0 mechanisms listed in [Not applicable](#not-applicable).

Everything outside the [signature profile](#signature-profile) fails closed.

## References

| Short name | Document |
|---|---|
| XMLDSig | XML Signature Syntax and Processing Version 1.1, W3C Recommendation 11 April 2013 |
| Exc-C14N | Exclusive XML Canonicalization Version 1.0, W3C Recommendation 18 July 2002 |
| C14N | Canonical XML Version 1.0, W3C Recommendation 15 March 2001 (rules Exc-C14N builds on) |
| XAdES | ETSI TS 101 903 V1.4.2 (namespace `http://uri.etsi.org/01903/v1.3.2#`) |
| TS 102 231 | ETSI TS 102 231 V3.1.2, Annex B (TSL format), B.6 (signature) |
| TS 119 612 | ETSI TS 119 612 V2.4.1, 6.1 (hash file `.sha2` only) |
| RFC 5280, RFC 6960 | X.509 path validation, OCSP |
| gemSpec_PKI | gemSpec_PKI V2.28.0 (with C_12791: A_28419, A_30044, A_30046) |
| gemSpec_TSL | gemSpec_TSL V1.25.0 |
| gemSpec_Krypt | gemSpec_Krypt V2.50.0 |
| gemKPT_PKI_TIP | gemKPT_PKI_TIP V2.14.0 |
| GemLibPki | gematik ref-GemLibPki 5.0.2, the Java reference implementation |

The gematik documents do not fix the canonicalization method, the transforms, the
reference layout or the XAdES properties of the TSL signature; gemSpec_Krypt fixes the
algorithms (A_17205) and requires XAdES (GS-A_4371-02, Tab_KRYPT_009). The profile below
fills the gap from the TSLs gematik actually publishes (PU sequence 10334, TU 10713) and
from the TSLs GemLibPki's signer produces; both agree on everything this document
requires.

The ECDSA `SignatureValue` encoding (r‖s, not DER) is not stated by gematik either; it
follows from XMLDSig 1.1 §6.4.3, the version gemSpec_Krypt references.

## Signature profile

```xml
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="…" TSLTag="…">
  …                                                   <!-- the TSL content -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
      <ds:Reference Id="R" URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#P">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>…</ds:SignatureValue>          <!-- base64(r ‖ s), 64 bytes -->
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>…</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#S">
        <xades:SignedProperties Id="P">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>…</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>…</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>…</ds:X509IssuerName>
                  <ds:X509SerialNumber>…</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#R"><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</TrustServiceStatusList>
```

Free in the profile: the values of the `Id` attributes, the presence of the `Id` on the
first reference, the namespace prefixes and redundant namespace declarations, whitespace
between elements, line breaks and `&#xD;` inside base64 content, further XAdES namespace
declarations (`xades141`), the form of `SigningTime` (gematik writes
`2026-09-27T23:00:07Z`, GemLibPki `2026-04-09T08:19:03.300+02:00`) and of
`X509IssuerName` (gematik `CN=GEM.TSL-CA3,…`, GemLibPki `cn=GEM.TSL-CA51 TEST-ONLY,…`).
`SignedDataObjectProperties` MAY be absent; if present, its `DataObjectFormat` MUST point
to the first reference. Nothing else is free.

## Rules

Result codes are named in [Result codes](#result-codes). Every profile violation and
every failed computation in part A is `xml_signature_error` unless another code is given;
the detail names the cause.

### A. XML and signature

| ID | Rule | Code |
|---|---|---|
| TSLSIG-001 | The input MUST be well-formed XML 1.0 in UTF-8. A document type declaration, entity declarations and references to external entities MUST be rejected. Processing instructions and comments outside the root element are allowed and not signed. Limits: at most 16 MiB, nesting depth 64, 64 attributes and namespace declarations per element. | `tsl_not_wellformed` |
| TSLSIG-010 | The root element MUST be `TrustServiceStatusList` (namespace `http://uri.etsi.org/02231/v2#`) and MUST have exactly one `ds:Signature` element in the whole document, as its last element child. | |
| TSLSIG-011 | `CanonicalizationMethod` MUST be `http://www.w3.org/2001/10/xml-exc-c14n#` without child elements (no `InclusiveNamespaces PrefixList`). | |
| TSLSIG-012 | `SignatureMethod` MUST be `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` without child elements, and the signer key MUST be on brainpoolP256r1 (A_17205, A_17206). P-256, other curves, RSA and RSASSA-PSS MUST be rejected. | |
| TSLSIG-013 | `SignedInfo` MUST contain exactly the two references of the profile, in that order. Reference 1: `URI=""`, transforms exactly `enveloped-signature`, `xml-exc-c14n#`. Reference 2: `Type="http://uri.etsi.org/01903#SignedProperties"`, `URI="#id"`, transforms exactly `xml-exc-c14n#`. No other attribute values, transforms, `InclusiveNamespaces`, XPointer or external URIs. | |
| TSLSIG-014 | All `Id` attributes in the document MUST be unique. Reference 2 MUST resolve to the `xades:SignedProperties` element inside this signature's `ds:Object/xades:QualifyingProperties`, whose `Target` MUST be `#` + the signature's `Id`. Only the attribute named `Id` identifies an element. | |
| TSLSIG-015 | Every `DigestMethod`, including the one in `CertDigest`, MUST be `http://www.w3.org/2001/04/xmlenc#sha256` (Tab_KRYPT_009). | |
| TSLSIG-016 | Exclusive C14N 1.0 without comments MUST be implemented as specified: the C14N 1.0 text and attribute escaping, attribute and namespace ordering, the "visibly utilized" namespace rule, `xml:*` attributes not inherited, the empty default namespace output only where needed. The document subset of reference 1 is the whole document without the `ds:Signature` element (enveloped-signature transform) and without comments. | |
| TSLSIG-017 | Each `DigestValue` MUST equal the SHA-256 of the canonical form of its reference; digests MUST be compared in constant time. | |
| TSLSIG-018 | `SignatureValue` MUST be base64 (whitespace including `&#xD;` ignored) of exactly 64 bytes, read as `r ‖ s` with 32 bytes each, `0 < r < n` and `0 < s < n` for the brainpoolP256r1 order `n`. The signature is verified over the canonical `SignedInfo` (Exc-C14N, TSLSIG-016). Implementations whose ECDSA API takes DER convert `r ‖ s` to DER. | |
| TSLSIG-019 | XAdES is mandatory (Tab_KRYPT_009, A_17360): exactly one `ds:Object` containing one `xades:QualifyingProperties` with one `xades:SignedProperties`, referenced by reference 2. Unsigned properties MUST be ignored. | |
| TSLSIG-020 | `SigningCertificate` MUST contain exactly one `xades:Cert`. Its `CertDigest` MUST equal the SHA-256 of the DER of the `KeyInfo` certificate; this binds the signer. `X509SerialNumber` MUST equal the certificate's serial number. `X509IssuerName` is not compared as a string, since producers write it differently; the certificate chain authenticates the issuer. | |
| TSLSIG-021 | `SigningTime` MUST be present and an `xsd:dateTime`. It is informational: no decision depends on it. | |
| TSLSIG-022 | `KeyInfo` MUST contain exactly one `X509Data` with exactly one `X509Certificate`, parsable as DER X.509 (TIP1-A_4084, Tab_PKI_712). No other `KeyInfo` content. | `tsl_cert_extraction_error` |
| TSLSIG-023 | After successful verification, the TSL content MUST be read from the canonical bytes of reference 1 (the octets that were hashed), never from the received bytes. | |

### B. Signer

| ID | Rule | Code |
|---|---|---|
| TSLSIG-030 | The TSL signer CA certificate of the environment is embedded in the implementation and pinned by its SHA-256 fingerprint (GS-A_4640, GS-A_4393). It is an ECDSA CA certificate (A_17688) with the Tab_PKI_212 profile. A TEST-ONLY anchor MUST NOT be usable in a production configuration. A configuration without an anchor is rejected when it is checked, not when a TSL arrives. | |
| TSLSIG-031 | The signer certificate MUST be signed by the anchor resolved by part E (TUC_PKI_004), and its AuthorityKeyIdentifier MUST equal the anchor's SubjectKeyIdentifier. | `certificate_not_valid_math`, `authoritykeyid_different` |
| TSLSIG-032 | The signer certificate MUST be valid at the validation time: `notBefore ≤ t ≤ notAfter` (TUC_PKI_002). So MUST the anchor. | `certificate_not_valid_time` |
| TSLSIG-033 | KeyUsage MUST be present and MUST be exactly `nonRepudiation` (TUC_PKI_011 step 3, Tab_PKI_252_01). | `wrong_keyusage` |
| TSLSIG-034 | ExtendedKeyUsage MUST be present and MUST be exactly `id-tsl-kp-tslSigning` (0.4.0.2231.3.0). | `wrong_extendedkeyusage` |
| TSLSIG-035 | The signer certificate MUST further match C.TSL.SIG (Tab_PKI_252_01, Tab_KRYPT_002a, A_17091): CertificatePolicies contains `oid_policy_gem_tsl_signer` (1.2.276.0.76.4.176); BasicConstraints absent or `cA=FALSE`; AuthorityInfoAccess with an OCSP URL; public key on brainpoolP256r1, uncompressed; certificate signature `ecdsa-with-SHA256`. | `tsl_signer_profile_violation` |

### C. Signer status

| ID | Rule | Code |
|---|---|---|
| TSLSIG-040 | When a network transport is available, the signer's status MUST be queried by OCSP at the URL in its AuthorityInfoAccess (A_30044 (3)), never at an address from a TSL. The response MUST be signed by the signer's CA or by a responder that CA certified for OCSP signing (RFC 6960, GS-A_4747, GS-A_4918). | `ocsp_signature_error` |
| TSLSIG-041 | Status `revoked` or `unknown`, a missing certHash extension or a certHash not matching the signer certificate MUST prevent the update. | `cert_revoked`, `cert_unknown`, `certhash_extension_missing`, `certhash_mismatch` |
| TSLSIG-042 | An OCSP status error (e.g. `tryLater`) MUST be retried at most 3 times, then the responder MUST NOT be asked for at least 5 minutes (A_30044 (4)). An unreachable responder, a response not matching the request, or implausible `producedAt`/`thisUpdate`/`nextUpdate` MUST prevent the update. | `ocsp_status_error`, `ocsp_check_revocation_error` |
| TSLSIG-043 | Without a network transport (TSL from a cache, a bundle, initial installation; TUC_PKI_001 variant 3a, gemSpec_PKI 8.1.2) the status is not queried; the result carries a warning. | `no_ocsp_check` (warning) |

### D. Update

| ID | Rule | Code |
|---|---|---|
| TSLSIG-050 | The TSL MUST be fetched only from the URL configured for the environment, never from `PointersToOtherTSL` or a backup address (A_30044 (1)). Before fetching it, the `.sha2` hash file MUST be fetched and compared with the hash of the current TSL; the TSL is fetched only if they differ or there is no current TSL (A_30044 (2)). A gzip content coding is removed before verification. | `tsl_download_error` |
| TSLSIG-051 | The set of CAs taken from the TSL MUST be replaced only by the CAs of a TSL that passed every rule of A–E (TIP1-A_2059). After the replacement it contains only CAs of that TSL. | |
| TSLSIG-052 | Once the signature is verified, processing MUST NOT abort: an entry that cannot be processed (unparsable certificate, missing element) is skipped and reported (TUC_PKI_001 note). The service type `http://uri.etsi.org/TrstSvc/Svctype/unspecified` MUST NOT make processing fail (A_17700). | |
| TSLSIG-053 | `Id` (root attribute) and `TSLSequenceNumber` of the new TSL are compared with the stored ones (TUC_PKI_019 steps 5–6): both equal → no update and no error; `Id` different and sequence number greater → update; anything else MUST be rejected. A TSL(ECC-RSA) sequence number below 10000 MUST be rejected (A_17685). The stored values survive restarts. | `tsl_id_incorrect` |
| TSLSIG-054 | With grace period `g` (0 to 30 days; 0 for central services, GS-A_4898): `t < NextUpdate` → valid; `NextUpdate ≤ t < NextUpdate + g` → valid with a warning; `t ≥ NextUpdate + g` → the TSL MUST NOT be used: no CA from it, no positive certificate check (GS-A_5336). | `validity_warning_1` (warning), `validity_warning_2` |
| TSLSIG-055 | The interval between update checks MUST NOT exceed 24 hours (GS-A_4899). | |

### E. Trust anchor and anchor change

GEM.TSL-CA3 (PU) expires on 2028-05-25, GEM.TSL-CA28 TEST-ONLY (RU/TU) on 2028-04-06. The
anchor for a TSL is resolved in this order; the signer certificate MUST be issued by the
anchor found:

1. **Announced and active** (TUC_PKI_013): the anchor a verified TSL announced, once its
   activation time has passed (TSLSIG-060 – TSLSIG-063).
2. **Embedded** (TSLSIG-030), unless an announced anchor has become active.
3. **Via roots.json**: a TSL signer CA issued by a GEM root CA that the A_28419
   cross-certificate walk of roots.json authenticated (TSLSIG-064 – TSLSIG-067). The TSL
   signer CAs are issued by the root CAs (GEM.TSL-CA3 by GEM.RCA4, GS-A_4736); a TSL
   signer CA under a verified root is as authentic as the embedded one. This covers an
   installation that missed the announcement (installed after the change, long offline,
   started from a bundle) without a new release. gemSpec_PKI only has ways 1 and 2; way 3
   applies the cross-certificate principle of A_17821 to the root path.

| ID | Rule | Code |
|---|---|---|
| TSLSIG-060 | A verified TSL is searched for services with `ServiceTypeIdentifier` `http://uri.etsi.org/TrstSvc/Svctype/TSLServiceCertChange`. None → nothing changes. | |
| TSLSIG-061 | More than one such service → all are ignored. A certificate that does not parse, is not a CA certificate, or is not valid at its `StatusStartingTime` → it is ignored. These cases are reported; they never make the TSL invalid (TUC_PKI_013). | `multiple_trust_anchor`, `tsl_sig_cert_extraction_error` (reported, not failing) |
| TSLSIG-062 | The announced anchor is stored next to the active one; a later announcement replaces an earlier one. Stored state is re-verified when loaded: the announcing TSL is stored with it and verified again. | |
| TSLSIG-063 | The announced anchor becomes active at its `StatusStartingTime`, not earlier. From then on the embedded anchor is no longer used (GS-A_4645). | as TSLSIG-031 |
| TSLSIG-064 | Way 3 starts only if the signer's issuer is neither the active announced nor the embedded anchor. The candidate is a certificate of a TSP service of the TSL itself whose subject equals the signer's issuer and whose SubjectKeyIdentifier equals the signer's AuthorityKeyIdentifier (the current TSL signer CA is listed in the TSL, TIP1-A_4035, A_17665). Where the candidate came from is irrelevant; only the checks count. | `tsl_sig_cert_extraction_error` |
| TSLSIG-065 | The candidate MUST be issued by a root CA authenticated by the roots.json walk (signature, AKI = SKI, validity of both at `t`). TEST-ONLY roots only in non-production configurations, as for any other chain. | `certificate_not_valid_math`, `certificate_not_valid_time` |
| TSLSIG-066 | The candidate MUST match the TSL signer CA profile (Tab_PKI_212/213, A_17658): BasicConstraints `cA=TRUE, pathLenConstraint=0`; KeyUsage contains `keyCertSign`; subject OU `TSL-Signer-CA der Telematikinfrastruktur`; CertificatePolicies contains `oid_policy_gem_or_cp` (1.2.276.0.76.4.163); public key on brainpoolP256r1. | `tsl_signer_profile_violation` |
| TSLSIG-067 | The candidate MUST NOT be older (`notBefore`) than the anchor in use without it: the active announced anchor, otherwise the embedded one. With a network transport its status MUST be `good` by OCSP at the URL in its AuthorityInfoAccess (the root's responder), with TSLSIG-040 – TSLSIG-042 applied to it; without, TSLSIG-043. | `tsl_signer_profile_violation`, codes of TSLSIG-041/042 |
| TSLSIG-068 | The result names the way the anchor was found (`embedded`, `announced`, `roots`), and a change of the anchor between two updates is reported. | |

### F. CA status

| ID | Rule | Code |
|---|---|---|
| TSLSIG-070 | A CA taken from the TSL is used according to its `ServiceStatus` (Tab_PKI_271): `http://uri.etsi.org/TrstSvc/Svcstatus/inaccord` → usable; `http://uri.etsi.org/TrstSvc/Svcstatus/revoked` → a certificate it issued is valid only if its `notBefore` is before the CA's `StatusStartingTime` (TUC_PKI_018 step 5, TIP1-A_2068); any other status → not usable. | `ca_certificate_revoked_in_tsl` |

### G. General

| ID | Rule |
|---|---|
| TSLSIG-080 | Every step is checked and fails closed with exactly one result code; nothing from a TSL is used before every step has succeeded (GS-A_4637, GS-A_4829, TIP1-A_2184). |

## Result codes

The codes are the message short names of gemSpec_PKI Tab_PKI_274 (GS-A_4751-01), in lower
case, with their number. GemLibPki's names are given for comparing logs.

| Code | No. | Kind | GemLibPki | Rules |
|---|---|---|---|---|
| `tsl_cert_extraction_error` | 1002 | error | `TE_1002_TSL_CERT_EXTRACTION_ERROR` | 022 |
| `multiple_trust_anchor` | 1003 | report | `SE_1003_MULTIPLE_TRUST_ANCHOR` | 061 |
| `tsl_sig_cert_extraction_error` | 1004 | report / error | `TE_1004_TSL_SIG_CERT_EXTRACTION_ERROR` | 061, 064 |
| `tsl_download_error` | 1006 | error | `TE_1006_TSL_DOWNLOAD_ERROR` | 050 |
| `tsl_id_incorrect` | 1007 | error | `SE_1007_TSL_ID_INCORRECT` | 053 |
| `validity_warning_1` | 1008 | warning | `SW_1008_VALIDITY_WARNING_1` | 054 |
| `validity_warning_2` | 1009 | error | `SW_1009_VALIDITY_WARNING_2` | 054 |
| `tsl_not_wellformed` | 1011 | error | `TE_1011_TSL_NOT_WELLFORMED` | 001 |
| `xml_signature_error` | 1013 | error | `SE_1013_XML_SIGNATURE_ERROR` | 010 – 021 |
| `wrong_keyusage` | 1016 | error | `SE_1016_WRONG_KEYUSAGE` | 033 |
| `wrong_extendedkeyusage` | 1017 | error | `SE_1017_WRONG_EXTENDEDKEYUSAGE` | 034 |
| `certificate_not_valid_time` | 1021 | error | `SE_1021_CERTIFICATE_NOT_VALID_TIME` | 032, 065 |
| `authoritykeyid_different` | 1023 | error | `SE_1023_AUTHORITYKEYID_DIFFERENT` | 031 |
| `certificate_not_valid_math` | 1024 | error | `SE_1024_CERTIFICATE_NOT_VALID_MATH` | 031, 065 |
| `ocsp_check_revocation_error` | 1029 | error | `TE_1029_OCSP_CHECK_REVOCATION_ERROR` | 042, 067 |
| `ocsp_signature_error` | 1031 | error | `SE_1031_OCSP_SIGNATURE_ERROR` | 040, 067 |
| `ca_certificate_revoked_in_tsl` | 1036 | error | `SE_1036_CA_CERTIFICATE_REVOKED_IN_TSL` | 070 |
| `no_ocsp_check` | 1039 | warning | `SW_1039_NO_OCSP_CHECK` | 043 |
| `certhash_extension_missing` | 1040 | error | `SE_1040_CERTHASH_EXTENSION_MISSING` | 041, 067 |
| `certhash_mismatch` | 1041 | error | `SE_1041_CERTHASH_MISMATCH` | 041, 067 |
| `cert_unknown` | 1044 | error | `TW_1044_CERT_UNKNOWN` | 041, 067 |
| `cert_revoked` | 1047 | error | `SW_1047_CERT_REVOKED` | 041, 067 |
| `ocsp_status_error` | 1058 | error | `TE_1058_OCSP_STATUS_ERROR` | 042, 067 |
| `tsl_signer_profile_violation` | – | error | – (own code; gematik has none for it) | 035, 066, 067 |

`validity_warning_2` is a warning in Tab_PKI_274 but stops the use of the TSL; here it is an
error. `cert_unknown` and `cert_revoked` are warnings there because they describe the
checked certificate; for the TSL signer they stop the update.

Codes of Tab_PKI_274 never produced, and why:
- `tsl_init_error` 1001: an implementation without a valid TSL reports the error of the
  failed step;
- `tsl_download_address_error` 1005: no `PointersToOtherTSL` (TSLSIG-050);
- `tsl_schema_not_valid` 1012: no schema validation ([Scope](#scope));
- `tsl_ca_not_loaded` 1042: the anchor is embedded; its absence is a configuration error
  (TSLSIG-030).

## Algorithm

```text
update(state, transport, t):
  hash ← transport.get(url_sha2)                                   # TSLSIG-050
  if state.tsl ≠ ∅ and hash = state.hash:
      return check_grace(state.tsl, t)                              # TSLSIG-054
  bytes ← transport.get(url_xml)                                   # TSLSIG-050
  verified ← verify(bytes, state, t)                                # A, B, E
  if transport ≠ ∅: check_ocsp(verified.signer, t)                  # C
  else: warn no_ocsp_check                                          # TSLSIG-043
  check_sequence(verified.tsl, state)                               # TSLSIG-053
  check_grace(verified.tsl, t)                                      # TSLSIG-054
  state.announced ← announcement(verified, state.announced)         # TSLSIG-060..062
  state.tsl, state.hash ← verified.tsl, hash
  replace CA set from verified.tsl                                  # TSLSIG-051, 052, 070

verify(bytes, state, t):
  doc ← parse(bytes)                                                # TSLSIG-001
  sig ← the single ds:Signature, last child of the root             # TSLSIG-010
  check SignedInfo against the profile                              # TSLSIG-011..015
  ref1 ← exc_c14n(doc without sig);  check digest                   # TSLSIG-016, 017
  props ← SignedProperties by Id inside sig; check digest           # TSLSIG-014, 019
  signer ← the single KeyInfo certificate                           # TSLSIG-022
  check CertDigest, serial; SigningTime present                     # TSLSIG-020, 021
  anchor, way ← resolve_anchor(signer, doc, state, t)               # part E
  check signer under anchor, validity, KU, EKU, profile             # TSLSIG-031..035
  check r‖s over exc_c14n(SignedInfo) with signer's key             # TSLSIG-012, 018
  return { tsl: parse_tsl(ref1), signer, anchor, way }              # TSLSIG-023

resolve_anchor(signer, doc, state, t):
  if state.announced active at t and issued signer: return it, announced   # TSLSIG-063
  if no announced anchor active at t and embedded issued signer:
      return embedded, embedded                                             # TSLSIG-030
  candidate ← TSL service certificate matching signer's issuer and AKI      # TSLSIG-064
  check candidate under a roots.json root, profile, age, OCSP               # TSLSIG-065..067
  return candidate, roots
```

The order may differ, if the result is the same (TIP1-A_2174); in particular, the XML
profile can be checked before the signer certificate, as above, though TUC_PKI_019 checks
the signer first.

## Requirement mapping

| Document | Requirement | TSLSIG |
|---|---|---|
| gemSpec_TSL | TIP1-A_4083 (signature mandatory, TS 102 231 B.6, GS-A_4371) | 010 – 021 |
| | TIP1-A_5121 / Tab_PKI_712, TIP1-A_4084 | 022 |
| | A_17684 (TSL(ECC-RSA) ECDSA-signed) | 012 |
| | A_17680-02, TIP1-A_4064, TIP1-A_5119 | 050 |
| | A_17685 (sequence number range) | 053 |
| | TIP1-A_4035, A_17664, A_17665 (TSL signer CA listed in the TSL) | 064 |
| gemSpec_Krypt | GS-A_4371-02 / Tab_KRYPT_009, A_17360 | 015, 019 – 021 |
| | A_17205, A_17206 | 012 |
| | GS-A_4357-02 / Tab_KRYPT_002a, A_17091, A_23139 | 035 |
| | GS-A_4393 | 030 |
| | [XMLDSig] (§6.4.3: r‖s) | 018 |
| | [XMLCan_V1.0] | 016 |
| gemSpec_PKI | A_17688, GS-A_4640, GS-A_4641, GS-A_4748, GS-A_4744 / Tab_PKI_212 | 030 |
| | GS-A_4642 TUC_PKI_001 steps 2 – 7, variants 2a, 3a, error 3b, notes | 022, 040 – 043, 051, 052 |
| | GS-A_4643 TUC_PKI_013, GS-A_4645 | 060 – 063 |
| | GS-A_4736, GS-A_4744 / Tab_PKI_212/213, A_17658, A_17821 (cross-certificate principle) | 064 – 068 |
| | A_28419 (roots.json walk) | 065 |
| | GS-A_4648 TUC_PKI_019 | 050, 053, 054 |
| | GS-A_4649 TUC_PKI_020 step 2 (step 3 out of scope) | 001 |
| | GS-A_4650 TUC_PKI_011 (with TUC_PKI_002, TUC_PKI_004) | 022, 030 – 034 |
| | GS-A_4745-01 / Tab_PKI_252_01 | 033 – 035 |
| | GS-A_4747, GS-A_4918 | 040 |
| | GS-A_4651 TUC_PKI_012 | 010 – 021 |
| | GS-A_5336, GS-A_4898, GS-A_4899 | 054, 055 |
| | A_30044 (1) – (4) | 040 – 042, 050 |
| | A_17690 | 050 |
| | A_17700 | 052 |
| | Tab_PKI_271, TUC_PKI_018 step 5 | 070 |
| | GS-A_4637, GS-A_4829, GS-A_4751-01 | 080, [Result codes](#result-codes) |
| gemKPT_PKI_TIP | TIP1-A_2040, TIP1-A_2041 | 010 |
| | TIP1-A_2049, TIP1-A_2072 | 053 |
| | TIP1-A_2059 | 051 |
| | TIP1-A_2075 | 060 – 063 |
| | TIP1-A_2174 | [Algorithm](#algorithm) |
| | TIP1-A_2184 | 080 |
| | TIP1-A_2046, TIP1-A_2068 | 070 |
| | TIP1-A_2050, TIP1-A_2051, TIP1-A_2489, TIP1-A_2185 | 054 |

### Producer requirements

Requirements on the TSL service, not on the verifier. They are checked by conformance tests
on the published TSLs of PU, RU and TU; a TSL violating them is a finding to report, not a
reason to relax a rule:

| Requirement | Checked |
|---|---|
| TIP1-A_4086 | `Id` contains the issue date `YYYYMMDDhhmmssZ` of `ListIssueDateTime` |
| TIP1-A_4087 | TSL date fields have the form `YYYY-MM-DDThh:mm:ssZ` |
| GS-A_4897, GS-A_5214 | `NextUpdate − ListIssueDateTime ≤ 30 days` |
| TIP1-A_4016, GS-A_3080 | signer certificate validity ≤ 5 years |
| TIP1-A_3994 | signer key ≠ anchor key |
| A_17658 | anchor issued by a GEM root CA of the same key generation |
| TIP1-A_4076-01, TIP1-A_4449 | signer AIA points to the TSL OCSP responder of the environment, which answers `good` |
| TIP1-A_4036 | the published TSL verifies in every verifier of the interoperability matrix |

### Not applicable

TI-1.0 mechanisms that the Internet profile (A_30044, A_30046) replaces:
- TUC_PKI_016, TUC_PKI_017 (download addresses from `PointersToOtherTSL`, backup
  addresses);
- TUC_PKI_005 and TIP1-A_2142 (OCSP address from the TSL's `ServiceSupplyPoint`), and the
  TUC_PKI_001 note to take the signer's OCSP address from the stored TSL;
- GS-A_5215 (tolerances, replaced by the caching rule A_23225);
- TUC_PKI_021 (CRL);
- A_17689, A_17820 (change between the RSA and ECC-RSA trust spaces; only the ECC-RSA TSL
  is supported). From A_17821 the sequence number range and the cross-certificate
  principle are taken.

## Deviations

From GemLibPki 5.0.2, each with a test in the corpus:

| GemLibPki | This specification | Why |
|---|---|---|
| KeyUsage must contain `nonRepudiation` | exactly `nonRepudiation` (TSLSIG-033) | Tab_PKI_252_01 allows no other bit |
| Signer policy not checked (`CERT_TYPE_ANY`) | `oid_policy_gem_tsl_signer` required (TSLSIG-035) | Tab_PKI_252_01 |
| Algorithms and transforms as accepted by xades4j/Santuario | fixed profile (TSLSIG-011 – 015) | fail closed, no algorithm downgrade, no transform-based attacks |
| `Id` and sequence number both equal → `SE_1007` | no update, no error (TSLSIG-053) | TUC_PKI_019 step 6 |
| XSD validation (`TE_1012`) | none | decided: gematik's signature vouches for the content |
| Anchor only embedded or announced | also via roots.json (TSLSIG-064 – 067) | anchor change without a release |

From gemSpec_PKI:
- TSLSIG-035 and TSLSIG-066 check more than TUC_PKI_011 (the full certificate profiles).
- TUC_PKI_001 step 6 forbids content checks of the CA certificates taken from the TSL;
  implementations MAY keep only CAs a verified root signed (as `ti-pki` does), which is
  stricter and does not affect the TSL rules here.
- Way 3 of part E.

## Security considerations

- **Signature wrapping (XSW).** Only the document element and the `SignedProperties` of
  this signature can be referenced (TSLSIG-013, 014); the content is read from the hashed
  octets (TSLSIG-023), so a second, unsigned copy of the content cannot be used.
- **Parser differentials.** One strict parser decides; the consumer reads the canonical
  octets of that parser's tree, not the input. DTDs and entities are rejected outright
  (TSLSIG-001), which rules out entity expansion and external entities.
- **Canonicalization.** Exclusive C14N is the only canonicalization; correctness is shown
  by the specification examples, the W3C interoperability vectors, differential testing
  against two independent implementations and property tests (CONFORMANCE.md).
- **Downgrade.** The algorithm set is a single fixed combination; the anchor cannot move to
  an older TSL signer CA (TSLSIG-067, TSLSIG-063).
- **Replay.** An older but validly signed TSL is rejected by the sequence number
  (TSLSIG-053); the grace period bounds how long a withheld update goes unnoticed
  (TSLSIG-054).
- **Time.** All checks use one injected validation time; `SigningTime` is not trusted
  (TSLSIG-021).
- **Local state.** Stored state (sequence number, announced anchor) has the integrity of the
  local file system. Lowering the stored sequence number re-enables a replay of older
  signed TSLs; it cannot introduce an anchor, since an announced anchor is stored with its
  signed TSL and verified again on load (TSLSIG-062).
- **Way 3.** It trusts what roots.json authenticates; its strength is that of the A_28419
  walk from the embedded root. The profile check (TSLSIG-066) keeps other CAs under the
  roots from acting as TSL signer CAs.

## Licence

Copyright 2026 gematik GmbH. Apache License, Version 2.0, see
[rust/LICENSE](../../rust/LICENSE). The test data under `testdata/gemlibpki/` comes from
gematik ref-GemLibPki (Apache-2.0, see its `NOTICE`); the W3C test vectors under
`testdata/w3c/` are under the W3C Software and Document License (see its README).
