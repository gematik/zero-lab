---
id: doc-3
title: 'RFC: TSL-Prüfung über die Detached-Signatur für Internet-Konsumenten'
type: other
created_date: '2026-11-01T16:11:00Z'
---

# RFC: TSL-Prüfung über die Detached-Signatur für Internet-Konsumenten

**Status: not written yet; conditional** (TASK-167). It is written only if the pre-release
requirements for internet and TI 2.0 consumers, which the maintainer will check first
(TASK-166, step 1), exclude verifying the TSL through the detached signature (`.sig`) and
the signer's OCSP response (`.ocsp`) in place of TUC_PKI_012. If they allow it, TASK-167
is closed with the citation and this document is archived.

What it will contain, in German with an English summary at the top:

- the facts with their requirement IDs: gemSpec_TSL V1.25.0 section 6.3.1.3 (A_21175 to
  A_21182), gemSpec_PKI V2.28.0 section 8.2.6 (A_30044), TUC_PKI_001 and TUC_PKI_012;
- the proposal: extend gemSpec_PKI 8.2.6 / A_30044 so that internet consumers MAY verify
  the TSL through `.sig` and `.ocsp` (A_21177 to A_21181) instead of the XML signature;
  publish `.sig` and `.ocsp` on the HTTPS `tsl.ti-dienste.de` hosts next to `.xml` and
  `.sha2`; widen A_21175's "Fallback-Verfahren für Konnektoren";
- the security argument: the same signer and anchor (TUC_PKI_011 unchanged), the same
  OCSP check, a signature over the exact bytes that are hashed and compared before every
  download, the TR-03111 signature format, and no XML canonicalization on the trust path;
- what stays unchanged: TUC_PKI_011, TUC_PKI_013, the TSL time parameters, sequence
  numbers and the update rules;
- open questions for the PKI team.

The analysis behind it is doc-2, section 6.
