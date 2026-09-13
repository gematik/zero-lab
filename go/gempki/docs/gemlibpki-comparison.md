# gempki against GemLibPki

Comparison of gempki with gematik's Java reference implementation
[ref-GemLibPki](https://github.com/gematik/ref-GemLibPki) (v5.0.2), which
implements TUC_PKI_018 (certificate check), TUC_PKI_006 (OCSP) and
TUC_PKI_001 (TSL) of gemSpec_PKI. Recorded so the deliberate deviations are
not mistaken for gaps.

## Deliberate deviations

gempki targets TI 2.0, where trust management is reduced to the gematik
root CAs: chains are built to the compiled-in roots (A_28419 cross-cert
walk), and the TSL only supplies the SubCAs currently in service and the
OCSP responders allowed to answer for them. Everything GemLibPki derives
from the TSL beyond that is therefore out of scope:

| GemLibPki | gempki |
|---|---|
| Issuer must be a TSL TSP service with ServiceStatus `inaccord`, certificate NotBefore after StatusStartingTime (SE_1036, SE_1032) | Parsed by `tsl`, not enforced |
| Certificate-type OID must appear in the issuer's TSL `ExtensionOID` list (SE_1061) | Parsed by `tsl`, not enforced |
| TSL XAdES signature, XSD validation, TSL ID and SequenceNumber against the current list (TE_1013, TE_1014) | Detached `.sig` verified over the TSL bytes; nothing else |
| TSL NextUpdate with grace period (TE_1015) | Printed by `ti pki tsl verify`, not enforced |
| Trust-anchor change announced in the TSL (TUC_PKI_013) | Roots come from roots.json |
| OCSP responder URL from the TSL supply point | AIA URL from the certificate, overridable |
| QES time-based validation with historical TSLs (TUC_PKI_030) | Not implemented |
| RSA profile variants | ECC only; the whole stack is ECC |
| OCSP response cache | Left to the caller |

## Implemented on both sides

Chain building and RFC 5280 path checks (gempki additionally enforces
IsCA, KeyCertSign and MaxPathLen), the certificate-type table of
gemSpec_PKI (KeyUsage, EKU, policies, role OIDs), OCSP responder
authorization (TSL listing, RFC 6960 same-CA, chain to root), OCSP
signature verification, CertID verification (serial and issuer hashes),
certHash verification (`RequireCertHash` makes the extension mandatory as
the TI does), and the TUC_PKI_006 time window on producedAt, thisUpdate
and nextUpdate with the 37.5 s tolerance.

## Open

Not intended and not yet done:

- Unknown critical extensions are not rejected (SE_1018);
  `crypto/x509` records them in `UnhandledCriticalExtensions` and nothing
  reads that field.
- The OCSP request carries no nonce, so a nonce in the response is not
  compared (TE_1057).
- An OCSP status of Unknown is surfaced as a result; GemLibPki fails it
  outright (TE_1060). The revocation mode table decides in gempki.
- Error codes are gempki's own vocabulary; the gemSpec_PKI codes
  (SE/TE/TW/SW_xxxx) are noted per code in `errors.go` but not exposed.
- `RequireCertHash` is off by default and `ti pki verify` does not switch
  it on; TI responders always include the extension, foreign trust
  circles may not.

## Reference oddity

GemLibPki's `CertificateType.CERT_TYPE_EGK_SIG` uses OID
`1.2.276.0.76.4.367` where gemSpec_OID Tab_PKI_405 lists `1.2.276.0.76.4.67`
for C.CH.SIG, so the reference misclassifies eGK signature certificates.
