# Operating the HSM proxy with a vendor's HSM

How an operator runs `hsm-proxy` against a vendor's HSM: what the image holds, how the vendor's
PKCS#11 module comes into the pod, and what was verified of each vendor's terms (TASK-389 #6).
The variables are in the [README](../README.md); the rules are servers.md rules 4, 6, 7, 27 and 29.

## What the image holds

The production image (`Dockerfile`) is the `hsm-proxy` binary on `gcr.io/distroless/cc`, built
without the features `simulator` and `conformance`. It holds no PKCS#11 module and no vendor
software. Everything in it is distributable with the EUPL-1.2:

| Part | Licence |
|---|---|
| `hsm-proxy` and the crates it is built from | EUPL-1.2; the dependencies MIT, Apache-2.0 (also with the LLVM exception), BSD-3-Clause, ISC or Unicode-3.0, as `just deny` checks against `rust/deny.toml`; a crate under several licences counts by an allowed one |
| The PKCS#11 declarations (`cryptoki-sys`) | a public-domain header from [latchset/pkcs11-headers](https://github.com/latchset/pkcs11-headers), not the OASIS headers, whose IPR policy is no OSI licence |
| `gcr.io/distroless/cc` (glibc, libgcc, libstdc++, OpenSSL's libcrypto) | Debian's packages under their own free licences |

The simulator image (`Dockerfile.simulator`) adds SoftHSM2, BSD-2-Clause, built from source. It
is for development and tests and never runs in production.

A vendor's module is proprietary. It is never part of either image, and nothing in this
repository redistributes it: the operator brings it into the pod at run time.

## Bringing a vendor's module into the pod

The module is a shared library the sidecar loads with `dlopen` (the one exception to rule 4).
The operator mounts it read-only and names it by path and SHA-256. The sidecar hashes the file
before loading it, refuses to start on another hash (rule 7), and reports path and hash at
start.

1. **An image of the module, made by the operator.** It holds the vendor's PKCS#11 library,
   the libraries it needs beyond glibc, libgcc, libstdc++ and libcrypto, and its configuration
   file, under one directory. It is built from the vendor's client package, signed, and kept in
   a private registry, as the vendor's terms require (below). It is never published.
2. **Mounted read-only into the sidecar.** Where the cluster supports image volumes, the module
   image is mounted directly as a volume. Elsewhere, an init container from that image copies
   the directory into an `emptyDir`, which the sidecar mounts read-only.
3. **Named and pinned:**
   - `HSM_PROXY_PKCS11_MODULE_PATH`: the library;
   - `HSM_PROXY_PKCS11_MODULE_SHA256`: its hash, from the build of the module image;
   - `LD_LIBRARY_PATH`: the module directory, if the library needs the others beside it;
   - the vendor's own variable that points at its configuration file, as the vendor documents.
4. **The PIN** is a file from a Secret (`HSM_PROXY_USER_PIN_PATH`), never a variable's value.
5. **Who reaches the HSM:** a network HSM is a peer outside the pod, so a NetworkPolicy allows
   the sidecar's egress to the HSM's address and port, and nothing else.

```yaml
initContainers:
  - name: hsm-module                 # only where image volumes are not available
    image: registry.internal/hsm-module@sha256:…
    command: ["cp", "-a", "/module/.", "/hsm-module/"]
    volumeMounts: [{ name: hsm-module, mountPath: /hsm-module }]
  - name: hsm-proxy
    image: registry.internal/hsm-proxy@sha256:…
    restartPolicy: Always            # a native sidecar: the workload starts after its startup probe
    env:
      - { name: HSM_PROXY_LISTEN_URL, value: unix:///run/hsm/proxy.sock }
      - { name: HSM_PROXY_PKCS11_MODULE_PATH, value: /opt/hsm/libvendorpkcs11.so }
      - { name: HSM_PROXY_PKCS11_MODULE_SHA256, value: "…" }
      - { name: LD_LIBRARY_PATH, value: /opt/hsm }
      - { name: HSM_PROXY_TOKEN_LABEL, value: zeta }
      - { name: HSM_PROXY_USER_PIN_PATH, value: /run/secrets/hsm/pin }
      - { name: HSM_PROXY_KEYS_PATH, value: /etc/hsm-proxy/keys.json }
      - { name: HSM_PROXY_GCM_IV, value: token }
    volumeMounts:
      - { name: hsm-module, mountPath: /opt/hsm, readOnly: true }
      - { name: hsm-socket, mountPath: /run/hsm }
      - { name: hsm-pin, mountPath: /run/secrets/hsm, readOnly: true }
      - { name: hsm-keys, mountPath: /etc/hsm-proxy, readOnly: true }
    startupProbe:   { exec: { command: ["/hsm-proxy", "health", "ready"] } }
    readinessProbe: { exec: { command: ["/hsm-proxy", "health", "ready"] } }
    livenessProbe:  { exec: { command: ["/hsm-proxy", "health", "live"] } }
volumes:
  - { name: hsm-module, emptyDir: {} }
  - { name: hsm-socket, emptyDir: { medium: Memory } }
  - { name: hsm-pin, secret: { secretName: hsm-pin, defaultMode: 0440 } }
  - { name: hsm-keys, configMap: { name: hsm-proxy-keys } }
```

The workload's container mounts `hsm-socket` too. The pod sets no user or group IDs (rule 27):
the socket is for owner and group, and both containers share the pod's group.

`HSM_PROXY_GCM_IV` is `token` for an HSM that makes the AES-GCM IV itself, as HSMs in FIPS mode
do, and `random` for one that takes the caller's. Which one a module needs, the token suite
finds out (`tests/token_softhsm2.rs`, run with `TI_HSM_PKCS11_MODULE_PATH` pointed at the
module).

The keys are provisioned with the vendor's tools: outside the simulator the sidecar makes no
key, and refuses to start if a listed key is missing, of another kind, or extractable.

## What was verified of each vendor's terms

Researched 2026-11-19 from the vendors' own pages; the sources are in TASK-389. Nothing here is
legal advice, and none of these vendors has been tried with the sidecar yet (TASK-389 #8).

| Vendor | Simulator or test software | Terms found | Consequence |
|---|---|---|---|
| Utimaco (u.trust GP HSM) | a free simulator after registration at the support portal, 32-bit x86 Linux | EULA: "test and evaluation purposes only"; not to be made "available to third parties for payment or for free"; to be kept "in strict confidence" | usable by a registered developer and on a private runner; not in a public image or public CI; on Apple Silicon only under emulation |
| Thales (Luna) | none found; the client is behind the support portal; a 30-day cloud HSM trial with an account | the EULA was not found | not verified |
| Entrust (nShield) | none found; software for customers under maintenance | the container option pack is "licensed for internal Customer use only" | the module image stays inside the customer's registry |
| Nitrokey (NetHSM) | a public test image | its licence was not found | not verified |

Not verified, and to be before a vendor is named as supported: Utimaco's mechanism list,
brainpool and arm64 builds; the Luna EULA and whether its client needs a contract; Entrust's
Security World EULA and any emulator; the key attributes each module honours.
