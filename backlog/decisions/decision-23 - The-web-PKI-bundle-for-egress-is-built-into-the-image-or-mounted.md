---
id: decision-23
title: The web PKI bundle for egress is built into the image or mounted
date: '2026-11-18 21:34'
status: proposed
---
## Context

Rule 29 names the web PKI as the trust source for egress to public hosts: a bundle shipped in the image or mounted, and the system store where the image has one. Decision-12 downloads trust material under a hash that TLS vouches for, so the web PKI takes part in the freshness of that material. A `scratch` image has no system store, so the bundle comes from one of the two other places, and a deployment that sets nothing needs a default.

## Decision

Proposed, not decided. The maintainer picks the default:

1. **Built into the image.** The bundle is a pinned input of the reproducible build and part of the measured image (rule 7).
2. **Mounted.** The deployment provides the bundle as a file, named by a `*_PATH`, hashed and reported with the configuration.

## Consequences

- Option 1: the image works without a mount, and the measurement says which roots it trusts. A root that is distrusted, or a new one a host moves to, needs a new image; an old image keeps trusting what it shipped with.
- Option 2: roots change without a release. The bundle is then the deployment's assurance, outside the measurement unless its hash is part of the attested configuration, and an image started without the mount has no source and refuses egress (rule 17).
- Whichever is the default, the other stays a declared source of rule 29, never a fallback.
