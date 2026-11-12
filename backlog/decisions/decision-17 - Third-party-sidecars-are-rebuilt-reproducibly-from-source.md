---
id: decision-17
title: Third-party sidecars are rebuilt reproducibly from source
date: '2026-11-12T21:18:00Z'
status: accepted
---
## Context

The OPA container-image pattern (2026-11-12, TASK-302) runs the upstream OPA image unmodified, pinned by digest. docs/design/servers.md rule 7 requires reproducible builds of everything that runs, and rule 8 puts sidecars in the measured workload; an upstream image cannot be reproduced, so its measurement would rest on the vendor's build rather than on one we can repeat.

## Decision

Maintainer, 2026-11-12: third-party code that runs in a workload, sidecars such as OPA included, is rebuilt reproducibly from source with our pinned toolchain into a minimal image and measured like our own binaries. No upstream image is part of the TCB.

## Consequences

- servers.md rule 7 states it; TASK-169 (OPA) builds OPA from a pinned source revision.
- Each such component falls under the dependency rules (docs/conventions/dependencies.md) and its updates are deliberate changes.
- More build work per third-party component, in exchange for a measurement anyone can recompute.
