---
id: TASK-398
title: >-
  hsm-proxy image: distroless with the C runtime (rule 4 exception), and a
  simulator image with SoftHSM2 from source
status: In Progress
assignee: []
created_date: '2026-11-19 14:37'
updated_date: '2026-11-19 14:41'
labels:
  - rust
  - docker
  - hsm
dependencies:
  - TASK-389
references:
  - docs/design/servers.md
  - rust/ti-hsm-proxy
priority: medium
ordinal: 411000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The sidecar loads a PKCS#11 module with dlopen, which a static binary on scratch cannot do. Maintainer, 2026-11-19: the HSM proxy may be the exception to rule 4. The production image is the dynamically linked hsm-proxy on gcr.io/distroless/cc (glibc), without simulator and conformance; the vendor's module is mounted read-only and loaded only by its SHA-256 (rule 7). A separate simulator image for development and tests holds hsm-proxy built with the feature simulator and SoftHSM2 2.7.0 built from source (decision-17; Debian bookworm has 2.6.1, which lacks CKM_ECDSA_SHA256). Base images by digest. Dockerfile beside the crate, build context rust/, as the Go images have theirs beside the command.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 servers.md rule 4 names the HSM proxy as its one exception: dynamically linked on a distroless image with the C runtime, the module mounted and loaded by its SHA-256
- [x] #2 rust/ti-hsm-proxy/Dockerfile builds the production image and the simulator image as two targets, base images by digest, SoftHSM2 from its source archive checked by SHA-256
- [x] #3 Both images build, and the simulator image starts under an arbitrary UID with a read-only root filesystem (rule 27) and answers hsm-proxy health ready
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: rule 4 has the exception (dynamic linking for dlopen, distroless/cc, no module in the image, the vendor's mounted and loaded by its SHA-256, the software token in an image of its own). rust/ti-hsm-proxy/Dockerfile: targets hsm-proxy (50 MB) and hsm-proxy-simulator (52 MB); base images by digest (rust:1.99.0-bookworm, distroless/cc-debian12:nonroot); SoftHSM2 2.7.0 from the GitHub tag archive, checked by the SHA-256 Homebrew pins (Homebrew's two patches are for OpenSSL 4; bookworm has 3.0); distroless/cc already holds bookworm's libcrypto.so.3, so the module needs nothing beside it. Verified with docker (colima, arm64): both build; the simulator runs as 1000680000:0 with --read-only, --cap-drop ALL and no-new-privileges, tmpfs over the token directory and the socket's directory, answers health ready and health live with 0, and exits 0 on SIGTERM; the production image refuses HSM_PROXY_SIMULATOR=true and holds no SoftHSM2. Gap against rule 7: cargo fetches the crates at build time (no vendored sources), as the Go images fetch modules; not checked on x86_64.
<!-- SECTION:NOTES:END -->
