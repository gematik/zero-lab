---
id: decision-24
title: Workload certificates are short-lived and not checked for revocation
date: '2026-11-18 21:34'
status: proposed
---
## Context

Rule 29 pins the identity of a workload's peers and reloads certificates without a restart. It does not say whether a workload's certificate is checked for revocation. For TI certificates the rule is fixed the other way: their status is checked by OCSP as the specification requires. Without a statement, a reader will assume the same for workload certificates, and an implementation will either add a revocation check nobody operates a responder for or silently leave it out.

## Decision

Proposed, not decided. The maintainer chooses between:

1. **Short-lived, no revocation check.** Workload certificates live for hours, are renewed by rotation (rule 6, rule 29), and are not checked against OCSP or a CRL. Rule 29 says so explicitly, and names the longest lifetime a listener accepts.
2. **Revocation checked.** Workload certificates are checked like any other, which needs a responder or CRL of the issuing CA that every workload can reach.

## Consequences

- Option 1: taking a workload out of trust means not renewing its certificate, and takes effect within one lifetime, or at once by removing its identity from the allowlists of rule 29. No responder is on the request path. The issuer has to issue short lifetimes, and rule 29 has to refuse a certificate that lives longer than the bound.
- Option 2: revocation takes effect as fast as the responder's answers age. The responder becomes a dependency of every connection inside the deployment, with its own availability (rule 13) and its own failure rule (rule 16: deny when it cannot be asked).
- Either way the statement belongs in rule 29, next to the opposite rule for TI certificates.
