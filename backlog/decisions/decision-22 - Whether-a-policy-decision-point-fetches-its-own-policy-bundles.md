---
id: decision-22
title: Whether a policy decision point fetches its own policy bundles
date: '2026-11-18 21:34'
status: proposed
---
## Context

Rule 8 says a policy engine's policies are configuration under rule 7, mounted at start and never loaded at run time. Rule 30 makes every fetch from an external host egress through one client. A policy bundle that comes from elsewhere is, under both rules, the work of a producer: a CronJob from the same image that fetches, verifies and exports, as rule 8 has it for trust material.

Some deployments expect the policy decision point to fetch its policy bundles itself, as a standalone image downloads its own trust material (decision-12).

## Decision

Proposed, not decided. The maintainer chooses between:

1. **The producer fetches.** The policy decision point never downloads policies. A new bundle arrives as a mounted file and takes effect with a new start, so the measurement of rule 7 covers it.
2. **The policy decision point fetches** signed bundles through the egress client of rule 30, verifies them and takes them into use at run time.

## Consequences

- Option 1 changes no rule. A policy change is a rollout, and a standalone image without a producer has only the policies it was started with.
- Option 2 changes rule 8 ("never loaded at run time") and rule 7 (configuration that changes behaviour is measured or hashed and reported): the bundle's signer becomes a trust source of rule 29, the hash of the policies in force has to be reported as they change, and the audit record of rule 21 already carries it per decision. Replicas can disagree on the policy in force for the time of a download, which rule 22 has to cover.
