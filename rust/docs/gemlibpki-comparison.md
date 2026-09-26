# ti-pki against GemLibPki

Comparison of `ti-pki` with gematik's Java reference implementation
[ref-GemLibPki](https://github.com/gematik/ref-GemLibPki) (v5.0.2), which implements
TUC_PKI_018 (certificate check), TUC_PKI_006 (OCSP) and TUC_PKI_001 (TSL) of
gemSpec_PKI. Recorded so the deliberate deviations are not mistaken for gaps. It
follows `go/gempki/docs/gemlibpki-comparison.md` and notes where `ti-pki` decided
differently from `gempki`.

## Deliberate deviations

`ti-pki` targets TI 2.0, where trust management is reduced to the gematik root CAs:
chains are built to the roots from the A_28419 cross-certificate walk, and the TSL is
not authenticated at all. It only supplies candidate intermediates, each kept only if a
verified root signed it. Everything GemLibPki derives from an authenticated TSL is
therefore out of scope:

| GemLibPki | ti-pki |
|---|---|
| Issuer must be a TSL service with ServiceStatus `inaccord`, certificate NotBefore after StatusStartingTime (SE_1036, SE_1032) | Only `inaccord` CAs are candidates, and a root must have signed them; StatusStartingTime is parsed, not enforced |
| Certificate-type OID must appear in the issuer's TSL `ExtensionOID` list (SE_1061) | Not enforced; the certificate's own policies decide its type baseline |
| TSL XAdES signature, XSD validation, TSL ID and SequenceNumber against the current list (TE_1013, TE_1014) | No signature is checked, neither XMLDSig nor the detached `.sig` (gempki verifies the latter); the sequence number is parsed |
| TSL NextUpdate with grace period (TE_1015) | Schedules the next reload; staleness is bounded by `ReloadPolicy::hard_expiry` |
| Trust-anchor change announced in the TSL (TUC_PKI_013) | Roots come from roots.json |
| Only the end entity's validity period is checked; a CA's standing is its TSL status (a `revoked` status before the end entity's notBefore rejects, SE_1036), its own validity period is never checked | RFC 5280 path validation: every certificate of the chain must be valid at validation time, so an expired CA still listed in the TSL invalidates its certificates (e.g. GEM.SMCB-CA9 TEST-ONLY, expired 2025-08-28, while its SMC-Bs run until 2028). Kept deliberately, like gempki and zeta-sdk; keycloak-zeta follows the reference |
| A SubCA's standing is its TSL listing | Each SubCA is checked by OCSP at its root's responder, on by default |
| OCSP responder URL from the TSL supply point | AIA URL from the certificate, overridable (`OcspChecker::with_responder_url`) |
| OCSP responder authorized by its TSL listing (byte-identical to a listed OCSP service, any TSP) | RFC 6960 (the issuing CA, or a delegate it certified with id-kp-OCSPSigning), else a delegate of another CA of the same TSP: id-kp-OCSPSigning, valid now, certificate verified under a TSL CA a root signed, both CAs listed under one TSP; reported as an `ocsp_responder_not_rfc6960` warning. This accepts ehca (a GEM.KOMP-CA51 delegate answering for GEM.SMCB-CA51); the D-Trust responders under GEM.OCSP-CA1/3 stay rejected, as their CA is not in the TSL |
| QES time-based validation with historical TSLs (TUC_PKI_030) | Not implemented; validation at a past instant uses the current roots and TSL |
| RSA profile variants | RSA signatures verify (PKCS#1 v1.5, PSS); the type baselines are the ECDSA branch |
| OCSP response cache | Left to the caller; `OcspChecker::with_max_response_age` accepts cached answers |

## Implemented on both sides

Chain building and RFC 5280 path checks (`ti-pki` additionally enforces the CA flag,
keyCertSign and the path length constraint), the certificate-type table of gemSpec_PKI
(key usage, extended key usage, policies, role OIDs), OCSP signature verification,
CertID verification (serial and issuer hashes; requests use SHA-1 CertIDs, which TI
responders require), certHash verification (required by default, unlike gempki), and
the TUC_PKI_006 time window on producedAt, thisUpdate and nextUpdate with the 37.5 s
tolerance.

Critical extensions: `ti-pki` applies RFC 5280 §4.2 to every certificate of the chain but
the root, rejecting a critical extension it does not process
(`unrecognized_critical_extension`; name and policy constraints count as unprocessed).
GemLibPki's `CriticalExtensionsValidator` is stricter on the end entity: its critical
extensions must be exactly basicConstraints and keyUsage, reported as
`CUSTOM_CERTIFICATE_EXCEPTION`. Real TI certificates mark exactly those two, a few also
extendedKeyUsage, which `ti-pki` accepts. (gempki's comparison files this under SE_1018,
which in GemLibPki is `CERT_TYPE_MISMATCH`, the type-OID check `ti-pki` performs as
`policy_mismatch`.)

## Open

Not intended and not yet done:

- The OCSP request carries no nonce, so a nonce in the response is not compared
  (TE_1057); TI responders sign on demand, and the time window bounds replay.
- An OCSP status of Unknown is a result; GemLibPki fails it outright (TE_1060). The
  revocation table decides in `ti-pki`: an error under HardFail, a warning under
  SoftFail.
- Error codes are `ti-pki`'s (and `gempki`'s) own vocabulary; the gemSpec_PKI codes
  (SE/TE/TW/SW_xxxx) are noted per `ErrorCode` variant but not exposed.

## Reference oddity

GemLibPki's `CertificateType.CERT_TYPE_EGK_SIG` uses OID `1.2.276.0.76.4.367` where
gemSpec_OID Tab_PKI_405 lists `1.2.276.0.76.4.67` for C.CH.SIG, so the reference
misclassifies eGK signature certificates.
