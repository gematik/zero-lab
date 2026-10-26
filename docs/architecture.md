# Architecture

## Roles of the languages

**Rust is the maintained core:** PKI and TSL validation, JOSE with brainpool, the TI
protocols, smartcard and Konnektor access. It is the reference implementation of
zero-lab's TI building blocks: one core that runs unchanged in a CLI, a server, a browser,
an air-gapped installation and, through bindings, in other hosts.

**Go keeps what Go is best at:** servers and relying parties (`pdp`, `pep`, `zaddy`,
`bff`), their libraries (`oauth`, `oidf`, `dpop`, `nonce`, `kv`, `gemidp`), and the ePA
client (`epa`).

**Other languages arrive as bindings** to the Rust core for client platforms: Swift
(iOS, macOS), Kotlin and Java (Android, JVM), JavaScript and TypeScript through
WebAssembly. Each gets a profile ([languages](languages.md)) before its first code lands.

New cryptography or TI protocol cores are written in Rust and reach other languages as
described in [interop](interop.md); no language grows a second implementation of a core
without a shared specification.

The decision record behind this split, with the integration options weighed, is
[doc-1](../backlog/docs/doc-1%20-%20Rust-as-the-core-architecture-Go-review-integration-means-workflow.md).

## Layers

```text
 hosts       CLIs, servers, browser (WebAssembly), mobile and desktop apps (bindings)
               │
 adapters    the only code that does I/O: HTTP clients, executors, files, platform APIs,
             key storage (HSM, TPM, Secure Enclave, Konnektor); opt-in, never in a core
               │
 engines     protocol flows as data: IDP-Dienst, FHIR-Directory, Konnektor, reports
               │
 core        PKI and TSL validation, XML signatures, JOSE, PKCS#12
               │
 vocabulary  shared types (environment, tier), cache policy and store interface
```

A unit depends only downwards. Adapters are opt-in parts of the unit they serve (features,
packages); a check proves the core builds without them. The language profiles name the
units of each layer.

## Sans I/O

Engines model a protocol as data: they build requests and consume responses, and the host
performs them. A core does no network, file or clock access of its own:

- Time is a parameter (a clock interface or a `now` argument), never read from the system
  inside a core.
- Randomness comes from the crypto backend, never from a global the host cannot replace.
- The core does not log; it returns outcomes and reasons, and the host decides what to
  log.
- Configuration is data the host hands in; a core reads no environment variable, flag or
  file it was not handed.

## Transport independence

The host supplies HTTP (and any other transport) through a small interface; any client
works, and none is a dependency of the core. The host does not decide trust: certificate
and TLS peer verification follow the core's rules (below). The transport carries TLS
(including client certificates, with the core's verifier deciding trust), proxies,
connection reuse, timeouts and redirect policy; where a redirect is an answer of the
protocol (the IDP flow), the transport must not follow it. Interfaces carry no threading
assumptions that would exclude single-threaded hosts such as the browser. Asynchronous
where a host may need it (browser, servers), synchronous where the only host is
blocking; every synchronous implementation can serve an asynchronous interface.

## The host owns the transport, the core owns trust

Transport independence does not hand trust decisions to the host. Most client logic talks
HTTPS to TI endpoints (IDP-Dienst, FHIR-Directory, ePA, OCSP responders, TSL hosts), and a
host's TLS stack would verify those peers against the operating system's trust store with
its own defaults, which is wrong for the TI. So the contract is split:

- **The host decides** connections, proxies, timeouts, connection reuse, and which TLS
  library carries the bytes.
- **The core decides** whether a peer or a certificate is trusted, for every TI endpoint:
  the trust anchors (from the verified TSL and roots.json, never the system store), the
  validation profile per certificate type, the algorithm and key rules (for example no
  RSA end-entity certificates where the gematik rules forbid them), and the revocation
  rules (when OCSP is required, freshness, responder authorisation, stapled responses).
- **The seam is a verifier the core supplies** and the host's TLS stack must call: it
  receives the peer's chain, the server name and any stapled OCSP response, and returns
  the verdict with its reason. A host may not replace it with platform verification or
  weaken it; an adapter per TLS library (rustls, Go's `crypto/tls`, the platform stacks
  of the bindings) wires it in.
- **The rules are one specification** ([interop](interop.md#a-concise-shared-specification)),
  so a native implementation (Go) and the core (Rust) verify identically, with the same
  result codes, and the shared corpus proves it.

Endpoints outside the TI (an OpenID provider on the internet, a package registry) use
ordinary WebPKI verification; which endpoints are TI endpoints is configuration of the
core, not a choice of the host.

## Trust from verification only

Bytes are untrusted whatever delivered them: HTTPS, a mounted file, an offline bundle, a
cache, a mirror, a database. roots.json is verified by the cross-certificate walk from the
anchor compiled into the binary; the TSL against its signer CA; only the TSL's CAs that a
verified root signed are kept. A compromised source can therefore withhold or delay
updates, never inject a CA, and staleness is caught by the freshness policy. The same
holds for every store and upstream a server uses: a compromised one can deny service,
never grant access. Caches,
mirrors and transports can be swapped freely because none of them is security-relevant.

## Offline and air-gapped operation

Trust material (roots.json, the TSL) is loaded by composable loaders:

```text
Reloader ── FallbackLoader ─┬─ CachingLoader ── HttpLoader ── Transport
                            └─ StaticLoader ◄── Bundle (offline file)
```

- An air-gapped installation uses a static loader alone, from a bundle exported on a
  connected machine, or a file transport over mounted files (Kubernetes ConfigMaps).
- A bundle needs no signature: it is verified on import like any other source, and its
  anchor hash rejects one exported for another environment before verification.
- Freshness still applies offline: material ages out by its hard expiry, so a production
  air-gapped site imports a fresh bundle at least daily. Missing OCSP is reported as
  such, never silently treated as `good`.
- Non-production anchors and relaxed policies are not compiled into production builds at
  all, and a check proves their bytes are absent.

## Portability

Cores build for every host the architecture names: native targets, WebAssembly in the
browser and in Node, and, where the libraries below allow it, environments without an
operating system (Rust `no_std` + `alloc`). WebAssembly exports are pure: downloads,
caching and the clock belong to the caller, because the TI download hosts send no CORS
headers and OCSP responders speak plain HTTP. Builds favour verification speed over size.

## Bindings

Hosts do HTTP, engines stay sans I/O. Client platforms get generated bindings (uniffi for
Swift and Kotlin/Java, wasm-bindgen for JavaScript); servers in other languages reach the
core across a process boundary. How, and when a function is implemented natively instead,
is in [interop](interop.md).
