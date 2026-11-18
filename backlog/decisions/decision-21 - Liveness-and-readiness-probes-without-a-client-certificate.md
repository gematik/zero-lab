---
id: decision-21
title: Liveness and readiness probes without a client certificate
date: '2026-11-18 21:34'
status: proposed
---
## Context

Rule 23 puts admin, metrics, health and debug endpoints on their own listener with mTLS. Rule 8 asks for liveness and readiness that reflect real state. The kubelet cannot present a client certificate on an HTTP probe, and gRPC probes carry no TLS, so a probe cannot reach health on the admin listener as rule 23 has it.

## Decision

Proposed, not decided. The maintainer chooses between:

1. **A third listener** that serves only liveness and readiness, without authentication and without detail: a status code, no body that names a dependency, a version or a reason.
2. **An exec probe** from a subcommand of the same binary, which asks the admin listener or a Unix socket from inside the container. It works on a `scratch` image, since it needs no shell.

## Consequences

- Option 1 changes rule 23: health leaves the admin plane for a listener of its own, which NetworkPolicy restricts to the node. One more listener per server under rule 29, in plaintext on the pod address, which the confidential tier of decision-20 would have to allow for exactly this.
- Option 2 keeps rule 23 as it is. Each probe starts a process, which costs more than an HTTP call and counts against the pod's limits; the subcommand needs a credential or a socket to reach the admin plane, and the probe's timeout has to cover a process start.
- Either way the detail of health (which dependency failed) stays on the admin listener.
