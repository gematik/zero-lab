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
| A SubCA's standing is its TSL listing | Each SubCA is checked by OCSP at its root's responder, on by default |
| OCSP responder URL from the TSL supply point | AIA URL from the certificate, overridable (`OcspChecker::with_responder_url`) |
| OCSP responder authorized by its TSL listing | RFC 6960 only: the issuing CA or a delegate it certified with id-kp-OCSPSigning. Delegates of other CAs are rejected, e.g. ehca (a GEM.KOMP-CA51 delegate answering for GEM.SMCB-CA51) and the D-Trust responders under GEM.OCSP-CA1/3; gempki also accepts TSL-listed responders and a chain to any root |
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

## Open

Not intended and not yet done:

- Unknown critical extensions are not rejected (SE_1018).
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
