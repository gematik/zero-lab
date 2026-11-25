# Servers

The same rules bind server software in every language: everything deployed as a Docker
(OCI) workload, today `zero-pdp`, `zero-pep-proxy`, `zero-caddy`,
`zero-epa` and `metsubushi`, and any to come, together with everything that runs inside
such a workload. A helper (`ti-pki-helper`, `ti-idpd-helper`) is not a workload of its
own, but it runs inside one, as a child process or as a sidecar container; there it is
part of that workload and follows these rules. Client-side software (the `ti` CLI, the
bindings in apps) follows the other documents. Server software is built to run as a confidential workload: in an enclave,
with a minimal trusted computing base, horizontally scaled on Kubernetes, with
everything outside the workload untrusted.

1. **Transport independent.** The service logic takes typed requests and returns typed
   results; HTTP, RPC or socket handling is a thin adapter around it. The logic does not
   depend on a web framework, on where TLS ends, or on headers a proxy may set; proxy
   headers (`X-Forwarded-*`, client-certificate headers) are trusted only from configured
   peers.
2. **OWASP as the baseline.** Every endpoint is checked against the current OWASP Top 10
   and API Security Top 10, with ASVS as the checklist:
   - authorization on every request, deny by default, object-level checks (no access by
     guessing IDs), the same validation on every endpoint of a component;
   - strict input handling: parse into types before use, allowlists over blocklists,
     size, depth and count limits before work, unknown fields rejected, canonical form
     before comparison, no string-built SQL, URLs, paths, headers or HTML;
   - no SSRF: outbound fetches (JWKS, entity statements, metadata) only to allowlisted
     or trust-chain-derived hosts, no redirects to private ranges, timeouts and size
     limits;
   - output encoding by context, security headers, CSRF protection for cookie flows,
     rate limits per client and per key, uniform error responses that leak no internals;
   - replay protection (nonce, `jti`, DPoP) and clock-skew limits as protocol state, not
     an afterthought.
3. **Horizontally scalable.** Replicas are stateless and interchangeable: no session
   affinity, no state only in memory; sessions, nonces, replay caches and rate limits
   live in shared storage (the `kv` store) and are correct with any number of replicas. Per-replica
   caches are optimisations only. Operations that can be retried are idempotent.
4. **Minimal trusted computing base.** Workloads run in enclaves (confidential VMs or
   containers: SEV-SNP, TDX, Nitro, confidential Kubernetes). Inside: one measured image
   with a static binary and, where a helper is used, the helper beside it (no native
   library linked in, [interop](../interop.md)), a `scratch` or distroless image without
   shell or package manager, the fewest dependencies
   ([dependencies](../conventions/dependencies.md)). The host, the hypervisor operator, the Kubernetes
   control plane, the ingress and sidecars outside the enclave are not trusted.
   - **One exception: the HSM proxy.** A PKCS#11 module is a shared library loaded with
     `dlopen`, which a static binary cannot do, so the key provider sidecar of rule 6
     (`hsm-proxy`) is linked dynamically and runs on a distroless image with the C runtime
     (`gcr.io/distroless/cc`). Its image holds no module: the vendor's is mounted read-only
     and loaded only by its SHA-256 (rule 7), and the software token of the simulator is in
     an image of its own, never in production. No other workload or sidecar loads native
     code.
5. **All data is encrypted outside the workload.** TLS ends inside the workload, not at
   an ingress or sidecar outside the TCB; inside the cluster the deployment may protect it
   instead where the operator accepts plaintext (rule 29). Data at rest in `kv`, Redis, Postgres, files or
   backups is encrypted and authenticated by the workload (AEAD, with the record's key,
   tenant and type as associated data, so records cannot be swapped or replayed into
   another context); the store sees ciphertext only. Logs, metrics and traces carry no
   personal data, tokens or secrets.
6. **Key provisioning bound to attestation.** Keys and secrets are released to a workload
   only after its attestation is verified (a KMS or key broker with a release policy on
   the measurement), delivered as files (`*_PATH`), never baked into images, environment
   variables or the kv store. Workload keys follow the [private-key rules](keys.md) and rotate
   with an overlap (rule 22): the new key is added before it is used and the old one
   removed once nothing needs it, each step a rollout (rule 8); credentials are
   short-lived where the peer allows. A workload's TLS key is generated inside the workload, and its
   certificate is issued only after the attestation is verified (a CSR bound to the
   evidence, or SPIRE with a TEE node attestor and its agent inside the confidential VM);
   a key from a cert-manager Secret or a node-local SPIRE agent was made outside the
   enclave and does not qualify ([decision-16](../../backlog/decisions/)). An HSM or
   KMS that holds a workload key is part of the workload's trusted base, and its key
   policy admits only this workload, proven by attestation and a workload identity the
   platform provides (the SPIFFE Workload API where it is mounted), never by a credential
   in a file. The channel is a cloud KMS API or a key provider sidecar (the pattern of the
   Kubernetes KMS plugin), on a Unix socket inside the pod or inside the cluster as rule 29
   has it.
   - **No private key crosses the channel.** What crosses is what each operation needs: a
     digest or a message to sign, and for a key-encryption key the data key it wraps or
     unwraps, in the clear. On the pod's socket the sidecar is in the workload's trust
     domain, which holds that data key anyway: it serves the keys it is configured with and
     does not ask who calls. Outside the pod, who may call is rule 29's, and per key the
     HSM proxy's (gemSpec_ZETA A_28830).
   - **The vendor's library is in neither image.** The workload's image never holds it,
     and the sidecar's image does not either: the operator mounts the module read-only and
     the sidecar loads it only if its SHA-256 is the configured one (rules 4 and 7).
7. **Attestation friendly, signed workloads.** Builds are reproducible (pinned toolchain,
   base images by digest, `-trimpath`, no build-time network for code), images are
   signed with provenance and an SBOM, a vulnerability scan of the image is a CI gate, and
   the measured image contains everything that runs: no code or plugins loaded at runtime,
   except the HSM's PKCS#11 module of rule 4, loaded only from a read-only mount and only if
   its SHA-256 is the configured one, which is reported with the configuration.
   Third-party code that runs in the workload, a sidecar such as OPA included, is rebuilt
   reproducibly from source like our own, never taken as the vendor's image
   ([decision-17](../../backlog/decisions/)). Configuration that changes behaviour is
   part of the measurement or hashed and reported. A workload exposes its version and
   build digest, and verifies the attestation of peers where hardware binding matters.
8. **Kubernetes, Docker and sidecars as untrusted neighbours.** Run as non-root with a
   read-only root filesystem, no capabilities, seccomp `RuntimeDefault`, resource limits;
   every container, sidecars included, is probed as rule 31 has it;
   SIGTERM drains and shuts down gracefully; what a process runs with is read at start and
   changed by a rollout, with the TI's trust material as the one exception (below). Trust
   material comes one of two ways, outside the request path, and consumers keep nothing of it
   on disk: from mounted files written by a producer (a CronJob from the same image that
   fetches, verifies and exports the set; an operator's import on an air-gapped site), or, for
   a standalone image, from the workload's own background download from the fixed hosts of
   the specification, under a hash that TLS vouches for
   ([decision-12](../../backlog/decisions/)).
   - **Read at start, changed by a rollout.** Configuration, TLS material (certificates,
     keys, CA bundles, allowlists) and keys are read and checked once, at start, and fixed
     for the life of the process: what rule 7 reports and attestation measures is what
     runs. A change is a new rollout: the deployment rolls the pods when a mounted Secret
     or ConfigMap changes (a checksum annotation, a reloader, cert-manager's renewal), and
     the PodDisruptionBudget and rule 22 keep that free of dropped requests. No server
     watches or polls such a file, and none re-reads it on the request path.
   - **Refreshed at run time: the TI's trust material, and nothing else.** The TSL and the
     TI roots, OCSP responses, federation entity statements and their JWKS, and the
     discovery documents of IdPs are valid for less than a deployment cycle, and a
     restart does not make them newer. They are verification data, not configuration: the
     core verifies each before use (rule 4), a verified set replaces the old one as a
     whole, a failed refresh keeps the old set and raises a metric, and the age of the set
     in force is a metric (rule 14). They are refreshed outside the request path, by the
     background check that loads them. Other material joins this list only by a change of
     this rule, with the reason its validity is shorter than a rollout.
   - **One image, several deployments.** A helper ships in the product's image
     (`libexec/telematik`, [git and releases](../conventions/git-and-releases.md)) and
     runs either as a child process over stdio inside the container or as a sidecar
     container started from the same image with the helper as its command; protocol and
     client are the same in both modes.
   - **Sidecars inside the enclave** (a helper, OPA, a key provider) are reached over a
     Unix socket as rule 29 has it, in a shared memory-backed `emptyDir` (`medium: Memory`:
     a tmpfs in the guest's memory, where a disk-backed volume can be host storage the host
     sees and replaces), with a peer check
     (`SO_PEERCRED`; on Linux the peer's executable through a pidfd), have no network
     listener, receive no secret across the socket, bound their frames and version their
     handshake. A sidecar serves its client only the operations it needs and offers none
     that changes its configuration at run time (for OPA: `--authorization=basic` with a
     `system.authz` policy that allows one method and one decision path, and refuses
     policy and data writes); that the socket is reachable is not the restriction. They
     are part of the measured workload: their digests are in the same signed manifest and
     in the pod policy that attestation measures; native sidecar containers order their
     start, and their probes follow rule 31. Policy engines
     run only this way, never as a service in another pod, and their policies are
     configuration under rule 7, mounted at start and never loaded at run time.
   - Platform services (workload identity, mesh TLS, attestation) are consumed through
     their standard interfaces and never provided here. A sidecar outside the enclave
     gets only ciphertext or data that is public anyway. Mesh mTLS ends in a proxy that
     the mesh's control plane configures: it is defence in depth, and a workload's channel
     protection only where the operator accepts plaintext for a connection inside the
     cluster (rule 29).
9. **Cloud native preferred.** Standard, portable building blocks: OCI images,
   Kubernetes primitives (Deployments, probes, PodDisruptionBudgets, topology spread,
   NetworkPolicies, mounted Secrets and ConfigMaps), declarative configuration,
   OpenTelemetry or Prometheus (rule 14). Managed cloud
   services (KMS, attestation, databases) are welcome behind an adapter interface, so the
   core runs on any cloud and on premises; no vendor SDK in a core package.
10. **Stateless by cryptography first.** Shared state is a dependency (a store on the
    request path, replication, failover, ACID); prefer constructions that verify
    themselves:
    - nonces the server can check without storing them: an AEAD- or HMAC-sealed value
      with issue time, purpose and binding (client, key thumbprint), valid for a short
      window (DPoP `nonce`, OIDC `nonce`, `state`, CSRF tokens);
    - self-contained, signed access tokens (JWT, RFC 9068) with short lifetimes and
      sender-constraining (DPoP, mTLS), so resource servers validate them offline;
      revocation through short expiry rather than lookups;
    - sealed client-side state (encrypted, authenticated cookies or parameters with
      expiry and purpose in the associated data) instead of server-side sessions where
      the protocol allows.

    The sealing and signing keys are workload keys (private-key rules, provisioning on
    attestation), shared by all replicas through the key service and rotated with key IDs.
    What must still be single-use (authorization codes, refresh-token rotation, `jti` and
    DPoP proof replay inside the acceptance window) keeps the smallest possible state:
    only for the value's lifetime, keyed by a hash, and under the next rule.
11. **ACID for the security state that remains.** Authorization codes, refresh-token
    rotation, `jti` and DPoP proof replay sets, client registrations and consent are read
    and changed in transactions, and single-use values are consumed
    atomically (an atomic take such as `kv.Store.Take`, conditional writes), so two replicas can never both
    accept the same value. Such state lives in a store with real transactions (Postgres);
    a store without them (Redis) holds only data whose loss or staleness is safe.
12. **Caching is an optimisation, never a source of trust.** A cache holds verified
    results keyed by everything they depend on (input hash, configuration, tenant,
    trust-material version), with a bounded lifetime no longer than the data's own
    validity, explicit invalidation when trust material changes, and protection against
    stampedes. Negative results are cached briefly or not at all. A cache outside the
    workload is encrypted like any other store; losing it costs latency, never
    correctness.
13. **Survives the loss of a zone, securely.** Replicas and every dependency (database,
    KMS, key broker) span at least three availability zones; no component lives in one
    zone only.
    - **Workloads are active/active:** replicas in every zone serve traffic at once
      (topology spread constraints, PodDisruptionBudgets); losing a zone loses capacity,
      not service. This works because they are stateless (rules 3 and 10).
    - **Security state is active/passive per primary:** one writer (the Postgres primary)
      with synchronous standbys in other zones and automatic failover. A write is
      confirmed only once a second zone has it, so a failover can never make a used
      authorization code, refresh token or `jti` valid again. Active/active writes to
      security state only on a store whose consensus gives serializable transactions
      across zones; never with asynchronous multi-master replication.
    - **Across regions** the default is active/passive with an explicit failover:
      synchronous commits over region distances cost too much latency, and asynchronous
      ones can lose or replay single-use state. Stateless, sealed values (rule 10) are
      what make an active/active region setup possible at all.
    - Clocks are synchronised and skew is bounded, since expiry and replay windows depend
      on them. Zone failure and failover are tested, not assumed.
14. **Observable without leaking.** Every server emits metrics, traces and structured
    JSON logs to stdout, correlated by W3C trace context. The export fits the deployment:
    OpenTelemetry (OTLP push to a collector) or Prometheus (scraped exposition), or both;
    code instruments through one small internal interface so the exporter is a wiring
    choice at the edge (the command), and the exporter's library falls under the dependency rules. A
    scrape endpoint is on the admin listener, restricted by NetworkPolicy and
    authentication, never on the public port.
    - Rate, errors and duration per endpoint and per dependency (store, key service, helper
      sidecar, upstream IdPs), saturation per replica; SLOs per service with
      alerts on the error budget.
    - Security signals are first-class metrics with alerts, not log lines to grep:
      verification failures (TSL, signatures, attestation), replay attempts, rejected
      tokens by reason, rate-limit hits, authorization denials by policy, key-service
      errors, trust material age. A verification failure can mean tampering and is an
      error-level event at once.
    - Telemetry leaves the workload, so it is data outside the TCB: no tokens, keys,
      PINs, personal or health data, and identifiers (KVNR, Telematik-ID, client IDs
      where sensitive) only pseudonymised. No user or token values as metric labels.
    - Incoming trace context is untrusted: it is accepted for correlation only, never
      changes sampling into a cost attack, and never carries authorisation.
    - Libraries do not log or export; they return outcomes and reasons, and the server's
      adapter turns them into telemetry. Telemetry is never part of a security decision,
      and losing it costs visibility, not correctness.
    - Profiling and debug endpoints exist only on the admin listener, never on the public
      port.
15. **Hardened protocol profiles, not bare specifications.** Where a security profile
    exists, it is the baseline and deviations are documented: the OAuth 2.0 Security BCP
    (RFC 9700) and FAPI 2.0 Security Profile for the authorization server and its
    clients (PAR, PKCE with S256, sender-constrained tokens with DPoP or mTLS, exact
    redirect URIs, no implicit or password flows, short-lived codes); the OpenID4VC High
    Assurance Interoperability Profile (HAIP) for credential issuance and presentation to
    wallets (OID4VCI, OID4VP; wallet and key attestation verified, DPoP-bound tokens, SD-JWT
    VC and mdoc, the profile's algorithms only); the gematik profiles (ZETA, IDP-Dienst,
    VAU) where they are stricter. Optional security features of a specification are
    treated as mandatory unless a documented interoperability need says otherwise.
16. **Fail closed.** An error in authentication, authorization, verification, attestation
    or a dependency they need means deny, never allow. A decision call denies on a
    transport error, a timeout (its own, per call), a non-success status and a response
    without a decision (OPA's undefined `result`). Degraded modes are explicit and
    bounded (stale trust material only within its policy limits), never a silent
    default to permissive.
17. **Refuse to start with insecure configuration.** At start-up a production server
    validates its whole configuration and exits on a TEST-ONLY anchor, an in-memory
    store, disabled verification, a missing key, a relaxed policy or a debug endpoint,
    as `TrustConfig::validate(Tier::Prod)` does for trust material. Test-only code and
    material are not compiled into production builds (build features or tags; the
    language profiles name them). The image holds no peer address, transport mode or
    trust source: the deployment sets them through environment and mounted paths, which
    are measured or hashed and reported (rule 7), and a URL's scheme picks the mode
    (`unix://`, `https://`; rule 29 has the grammar). Start-up refuses every inconsistent
    combination: plaintext to a peer outside the pod the operator has not accepted (rule 29), TLS without a trust source, two
    trust sources for one connection, a client certificate without its key, a key and a
    certificate that do not match, a certificate that has expired or is not yet valid, an
    empty CA bundle, an mTLS peer without an expected name.
18. **Business APIs follow the gematik API rules, including versioning.** Every business
    API has a machine-readable OpenAPI contract in the repository, versioned as the rules
    require, and passes the gematik OpenAPI ruleset with no errors and no warnings. A
    breaking change only comes as a new major version, the previous one is served side
    by side through a published deprecation period, and contract tests hold the
    implementation to the contract.
    - **Where the rules are:** the ruleset is in gematik's internal GitLab project
      `dev-portal/api-tools` (`openapi/spectral/`); the `gematik-openapi-lint` skill in
      ti-skills explains each rule, its purpose and fix, and the ruleset's known gaps.
      Neither is public yet. The ruleset has no licence: link or clone it, never copy
      it, or excerpts of it, into this repository.
    - **How it runs:** `just api-lint` in `go/` (part of `just check`) lints every
      OpenAPI contract in the repository with Spectral against a local clone at
      `GEMATIK_API_TOOLS_DIR`, pinned to `API_RULESET_REV`. Without the clone it skips
      with a notice; internal CI sets `REQUIRE_API_LINT=1` and fails instead. Moving the
      pin is a deliberate change, like a dependency update.
    - **Writing a contract:** read the rule explanations (the `gematik-openapi-lint`
      skill or `openapi/rules-explained.md` in the ruleset) before writing, and run
      `just api-lint` before calling the contract done. Never reconstruct rules from
      memory.
    - **Known gap:** `path-must-include-version` matches only `/v1/` at the pinned
      revision, so a correctly versioned `/v2/` path fails; until the ruleset is fixed,
      such a finding is a documented exception, not a reason to keep a breaking change in
      `v1`.
    - When ti-skills and the ruleset are published, the references move to their public
      locations and the skip goes away.
19. **Per-tenant keys and crypto-shredding.** Data of a tenant, insured person or
    institution is encrypted under its own data key, wrapped by the key service; the key
    ID is part of the associated data. Deleting the key deletes the data everywhere,
    backups included, which is how erasure (GDPR Art. 17) is guaranteed for health data.
20. **Privacy by design for health data** (GDPR Art. 9, SGB V): collect only what the
    purpose needs, bind data to its purpose, define retention and deletion per data type
    and enforce them in code, pseudonymise KVNR, Telematik-ID and similar identifiers
    wherever the plain value is not required.
21. **Tamper-evident audit trail, separate from operational logs.** Authentication,
    authorization decisions, consent, key use and administrative actions are written to
    an append-only, hash-chained or signed audit record with correlation IDs,
    pseudonymised, retained as the law and gematik require, and readable without the
    operational logging pipeline. An authorization decision's record carries the hash of
    the policies it was made under; a policy engine's own decision log stays off, as it
    holds the decision's input (rule 14).
22. **Mixed versions work.** During a rolling deploy versions N and N+1 run side by side:
    tokens, sealed values, stored records and messages from either are readable by the
    other; schema changes go expand, migrate, contract; keys rotate with an overlap in
    which old and new both verify.
    - **A server does not change its schema.** A server's database role may read and write
      rows and nothing else: it cannot create, alter or drop a table, so a compromised
      server cannot either. Schema steps are numbered and recorded in the database, and a
      migration job applies them before the rollout, with credentials of its own that no
      server holds. An expand step is applied while replicas of release N still run and
      restart; a contract step, which removes what N uses, only when none is left and only
      when asked for.
    - **A server checks the schema it finds** (rule 17): it does not start when a step it
      needs is missing, nor when a contract step it does not know was applied, and it
      starts on expand steps of a newer release. A deployment without a migration job (a
      compose file, a first installation by hand) may let the server apply expand steps
      itself, by a setting that is off unless set; its role then has the rights this rule
      otherwise takes away.
23. **A separate admin plane.** Admin, metrics, health and debug endpoints listen on their
    own port with their own authentication (mTLS), restricted by NetworkPolicy, except the
    bare probe path of rule 31, which the kubelet reaches without a certificate; nothing
    administrative is reachable on the public listener, and debug and profiling are not
    compiled into production builds.
24. **Resilient under load.** Timeouts on every outbound call and every phase of an
    inbound one; retries only for idempotent operations, with backoff, jitter and a
    budget; bounded queues, concurrency limits and load shedding before overload;
    rate limits per client and key; limits against slow clients, oversized headers and
    HTTP/2 abuse; a panic in a request ends that request with a generic 500, never the
    process.
25. **Signatures enforced at deploy time.** A Kubernetes admission policy (sigstore
    policy-controller, Kyverno or equivalent) admits only signed images with verified
    provenance, by digest; unsigned or tag-referenced images do not run.
26. **Tested as a server, not only as code.** End-to-end tests against the real protocol
    (as `go/pdp/e2e`), load tests against the latency budgets, a chaos test that takes a
    zone and a store primary down and checks that no single-use value is accepted twice,
    and dynamic scanning (OWASP ZAP or equivalent) of every exposed endpoint. A sidecar
    is tested at its socket: a process with another UID or executable is refused, a
    write to its configuration through its API is refused, and a stopped or slow sidecar,
    or one without a decision, leads to deny. Transport (rules 29 and 30) is tested on the
    image: the same image started in each mode (https, mTLS, unix, the http opt-out);
    a certificate rotation by rollout under load without a dropped request; a wrong SAN, an expired
    certificate and an unknown client refused; the egress client through a CONNECT proxy.
27. **Runs under any UID, as on OpenShift.** The platform picks the identity, not the
    image: OpenShift's `restricted-v2` SCC starts a container with an arbitrary UID from
    the namespace's range, primary GID `0` and no `/etc/passwd` entry, sets `fsGroup` and
    supplemental groups from the same range, and rejects a pod that asks for fixed IDs.
    Pod Security `restricted` on plain Kubernetes is the same minus the arbitrary UID. A
    workload that only works under the UID its image declares fails there, or is pushed
    to `anyuid`, which weakens rule 8 for the whole namespace.
    - **The image:** a numeric non-root `USER` (`65532`, never a name), so the kubelet
      can check `runAsNonRoot` without a `runAsUser`. Nothing depends on that UID: no
      lookup of user name or home in `/etc/passwd`, `HOME`, `TMPDIR` and cache
      directories set by environment. Everything the process reads is readable by group
      `0` or by others; every path it writes is owned by group `0` and group-writable
      (`chgrp -R 0 … && chmod -R g=u …`, or `COPY --chown=65532:0` with group write).
      Ownership by `65532:65532`, `1000:1000` or another group does not count, and
      neither does a world-writable directory without the sticky bit.
    - **Writes are known and few.** Each image lists the paths it writes at run time
      (cache, state, temporary files, sockets); each is a volume mount point or under
      `/tmp`, so the image runs with a read-only root filesystem and an `emptyDir` or
      PVC over each path. The process writes nothing else: no generated configuration
      under `/etc`, no `chown` or `chmod` at start, logs only to stdout and stderr.
    - **No privilege for ports:** listeners default to ports `>= 1024`; a public port
      below that is the Service's or the Route's mapping, never `NET_BIND_SERVICE` in the
      container.
    - **Manifests set no IDs.** Deployments, Jobs, CronJobs, init and sidecar containers
      set `runAsNonRoot: true` and leave `runAsUser`, `runAsGroup`, `fsGroup` and
      `supplementalGroups` to the platform. Where plain Kubernetes needs one (a volume
      type without ownership management), it sits in an overlay or value that one
      setting removes for OpenShift; a chart that sets IDs removes them on an explicit
      `null`, because Helm merges maps and a left-out key inherits the default. Mounted
      Secrets and ConfigMaps are readable without a known UID (`defaultMode` `0440` with
      `fsGroup`, or `0444`), and a Unix socket shared between containers is
      group-accessible through the shared `fsGroup`, with the peer check of rule 8 as the
      control rather than the UID.
    - **Bundled third-party parts** (ingress controller, operators, collectors) are
      either shown to run under `restricted-v2` with the deployment's values or left to
      the platform on OpenShift; ones that create cluster-scoped resources are optional.
    - **Tested both ways:** every image passes a start test under an arbitrary UID,
      `docker run --user 1000680000:0 --read-only --cap-drop ALL --security-opt
      no-new-privileges` with `--tmpfs` over its listed paths, up to readiness or the
      first expected missing dependency, and the rendered manifests of every deployment
      contain no numeric `runAsUser`, `runAsGroup` or `fsGroup` in the OpenShift profile.
      Before a release, the workloads run on OpenShift (OpenShift Local or OKD) in a
      project without `anyuid`.
28. **Every HTTP message is checked before the logic sees it.** Rule 2's strict input
    handling, spelled out for HTTP, following the OWASP Input Validation, HTTP Request
    Smuggling and Unvalidated Redirects cheat sheets and ASVS V5 (validation, sanitisation
    and encoding). It covers the requests a server receives and the responses of the calls it
    makes (to IDPs, federation members, backends and sidecars), which are untrusted input in
    the same way.
    - **Reject, never repair.** A value outside its grammar is refused. It is not trimmed,
      decoded again, truncated, case-folded or otherwise fixed up, because a repaired value
      is not the one that was signed, registered or meant. Values are compared in canonical
      form, and a value not in canonical form is refused, not normalised and then
      compared.
    - **Limits before work.** The adapter bounds the request line, header size and count,
      body size, JSON depth and member count, parameter count and each value's length
      before it parses or allocates anything that grows with the input. A response is
      bounded in the same way before it is read.
    - **Method and path.** Each route accepts its declared methods only: another gets 405
      with `Allow`, and method-override headers and parameters are ignored. A path is
      matched as received. Encoded `/`, `\` or NUL, `.` and `..` segments, double encoding
      and characters outside the route's grammar are refused, never cleaned up into a
      match.
    - **Parameters.** Each endpoint declares its parameters with a type, a grammar and
      limits; each value is parsed against them before use. A repeated parameter is
      refused (RFC 6749 §3.1). A parameter the endpoint does not know is refused on our own
      APIs, and ignored only where the protocol requires it (OAuth endpoints, RFC 6749 §3.1),
      never passed on. An empty value counts as absent where the protocol says so, and as
      invalid otherwise.
    - **Headers.**
      - `Host` (or `:authority`) is one of the configured names; URLs a server builds use
        its configured base URL, never the request's Host.
      - A body comes with the exact `Content-Type` the endpoint takes, and a charset other
        than UTF-8 is refused.
      - Request smuggling: a request with several differing `Content-Length`s or with
        obsolete line folding is refused. One with both `Content-Length` and
        `Transfer-Encoding` is refused, or its `Content-Length` is dropped before anything
        reads or forwards the body (RFC 9112 §6.3).
      - CR, LF and NUL in any header value are refused.
      - Proxy headers follow rule 1.
    - **Bodies.** A body is parsed strictly, not leniently:
      - JSON must be valid UTF-8, with no duplicate keys, numbers within their type's range,
        and unknown members refused where the format is ours (JSON Schema
        `additionalProperties: false` in the contract, rule 18);
      - form bodies follow the parameter rules above;
      - a JWS or JWE is checked against its compact form and size before it is decoded.
    - **Values.** Identifiers, codes, states, nonces, scopes and URIs each have an allowlist
      grammar of characters and length, ASCII unless the specification says otherwise. Free
      text has a length bound, valid UTF-8, no control characters and no bidi overrides.
      A URI is parsed and checked as a whole:
      - its scheme comes from an allowlist (https; `javascript:`, `data:` and `file:` never);
      - it has no user information;
      - its host is canonical, with no percent-encoded host delimiters.
    - **Redirects.** A redirect goes only to a target that is byte-equal to a registered
      one (an exact redirect URI, RFC 9700 §4.1.3), never one built from or prefix-matched
      against request input. Parameters added to a redirect are encoded for the query.
    - **Cookies.** Session cookies use the `__Host-` prefix, `Secure`, `HttpOnly` and
      `SameSite`. A cookie's value is bounded, parsed and authenticated before use. Cookies
      a server did not set are ignored.
    - **Output.** A value from a request or a response is encoded for the context it goes
      into: HTML, a header, a URL or a log field. Logs take values as structured fields,
      never by string concatenation, which prevents log injection. Errors name the field
      and the reason, never echo the value, and leave out stack traces and internals (rule
      2, uniform errors).
    - **Outbound responses.**
      - A call's response is checked before use: the status code expected for the
        operation, the `Content-Type`, the size, then the body with the same strict parsers.
      - An error response's text is kept as data, bounded and free of control characters,
        and never passed into HTML or headers.
      - A redirect is not followed unless the protocol makes it an answer (architecture,
        transport independence).
    - **One implementation, fuzzed.**
      - Each language has these checks once, as shared code the adapters call, not
        rewritten per handler. The profiles name it.
      - Every parser and validator has a fuzz target whose seeds are hostile input: CRLF
        and NUL injection, overlong and invalid UTF-8, bidi and zero-width characters,
        encoded separators, double encoding, deeply nested and duplicate-key JSON,
        oversized and malformed tokens, and huge numbers.
      - The targets assert properties: an accepted value matches its grammar; an error
        does not contain the input; a refused value never reaches the logic, the store or
        the network.
      - Dynamic scanning (rule 26) runs against the same endpoints.
29. **One transport grammar for listeners and peers, secure by default.** Rule 17's scheme
    that picks the mode, for every connection a server accepts or opens inside its
    deployment; connections to external hosts are rule 30.
    - **The URL is the mode.** Every listener and every peer is one URL, `https://`,
      `unix://` or `http://`; no separate TLS switch can disagree with its scheme. Without
      an explicit scheme it is https. Plaintext is an opt-out the deployment writes out as
      `http://`: it is logged at start and refused where the tier does not allow it.
    - **Inside the cluster, one of two.** A listener or peer outside the pod and inside the
      cluster is protected either by the workload or by the deployment; connections
      to hosts outside the cluster are rule 30. Inside the pod, a Unix socket needs neither,
      and neither does a loopback address (`127.0.0.1`, `::1`), which only the pod's own containers
      reach (maintainer, 2026-11-22).
      - **Own TLS or mTLS:** `https://`, terminated by the workload itself with the
        material below, and a client CA and an allowlist of identities for mTLS.
      - **Plaintext the operator accepts:** `http://`, with the deployment protecting the
        connection, by a mesh's mTLS or otherwise. The workload cannot tell whether
        anything does, so it does not guess and does not name it: the operator accepts
        plaintext explicitly, like terms of service, with a setting of its own beside the
        URL (`…_PLAINTEXT_ACCEPTED=true`). Unset, or any other value, a plaintext URL is
        refused at start; accepted, the acceptance is logged and reported (rule 7). The
        workload neither encrypts nor checks the caller then: the deployment does.
      - **Now and later.** For now accepted plaintext is allowed wherever the protection
        runs (maintainer, 2026-11-19). The target is the protecting proxy inside the
        enclave, in the pod and measured with it (rule 7), so that the channel still ends
        inside the TCB as rule 5 has it.
        - A proxy on the node never meets it: Istio's ambient ztunnel and Cilium's
          WireGuard or IPsec end the channel on the host and hold the keys of every pod
          there. A sidecar in the confidential pod meets it when the pod policy that
          attestation measures names its image and the traffic is redirected inside the
          guest; Contrast's mesh does both, an injected Istio or Linkerd sidecar needs
          its injection in the measured policy and redirection in the guest (Kata issue
          14137 for Istio's CNI).
        - The allowance stays while no deployment runs confidential (2026-11-23: none
          here does; gematik's ZETA Guard charts leave the mesh and its mode open). It
          goes when the first one does.
    - **TLS from files.**
      - Per listener and per peer: certificate, key and CA bundle, each a `*_PATH`. Who
        wrote the file is the deployment's assurance, not the server's concern (rule 6).
        The server never generates a self-signed certificate and has no option to skip
        verification.
      - mTLS is configuration, not a mode of its own: a listener with a client CA bundle
        requires client certificates; a peer with a certificate and key presents them.
      - Identity is pinned, not only chained: each peer has an expected name (DNS SAN or
        SPIFFE ID), an mTLS listener an allowlist of client identities. A valid chain
        under a shared CA does not say which workload is calling.
      - Read at start, rotated by a rollout (rule 8): a server whose key and certificate
        do not match, or whose certificate is not valid, does not start (rule 17).
        Certificate expiry is a metric with an alert well before the renewal is due, and
        an expired certificate fails readiness.
      - The profile is fixed: protocol version, curves and suites follow gemSpec_Krypt and
        are constants in code, not configuration.
    - **Unix sockets are first-class listeners.** Path sockets only, no abstract
      namespace. A socket is created under a restrictive umask, is group-accessible (rule
      27) and has the peer check of rule 8. A stale socket file is removed only when
      nothing answers on it. Plaintext over a Unix socket inside the pod counts as inside
      the workload.
    - **One declared trust source per connection.** A listener, a peer and the egress
      client each declare one source; none is implicit, and a connection without one is
      refused (rule 17). A source is never combined with another by fallback: if the
      declared one fails, the connection fails. The sources are:
      - a CA bundle from a path, for peers inside the deployment;
      - anchors compiled into the binary, for TI roots and the production tier check
        ([decision-11](../../backlog/decisions/));
      - trust material the workload verifies itself: the TSL, an OpenID Federation trust
        chain, an attestation root;
      - a workload identity bundle from the platform (SPIFFE), where it is mounted;
      - the web PKI, for egress to public hosts, as a bundle shipped in the image or
        mounted, and the system store where the image has one.
    - **Reported.** The mode of each listener and peer, a plaintext opt-out included, and
      the trust source of each connection are part of the reported configuration (rule 7).
      The admin listener shows, per listener and peer, the mode, the certificate
      fingerprint and expiry, and the trust source, never a key.
30. **Egress is a separate client with its own rules.**
    - **Two classes of peers.** Peers inside the pod or the cluster (OPA socket, kv,
      Postgres, key service) are configured per peer under rule 29 and never go through a
      proxy. Everything else is egress: trust material, OCSP, JWKS, entity statements.
    - **One egress client.** All outbound fetches to external hosts go through one client,
      which applies the allowlist of rule 2, the timeouts and limits of rule 24 and the
      response checks of rule 28.
    - **A forward proxy is supported, as an untrusted neighbour.**
      - The egress client honours `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, because
        operators and platforms set them. No other client reads them.
      - https goes through CONNECT only, so TLS still ends at the origin and the proxy
        sees host names and nothing else. A TLS-intercepting proxy is not supported: no
        extra CA is accepted for egress.
      - Proxy credentials are a secret: a proxy URL with user information in a variable is
        refused; credentials come from a `*_PATH` file
        ([naming and configuration](../conventions/naming-and-config.md)).
      - Whether a proxy is in effect, and its host, is part of the reported configuration
        (rule 7).
    - **Plain http only for self-verifying data.** OCSP responses and CRLs are signed and
      verified by the workload, so they may travel over http and through the proxy.
      Nothing else does.
31. **Every container's health is probed, and the three probes ask different questions.**
    - **Every container.** Each container of a workload, a sidecar as much as the main
      one, has a startup, a readiness and a liveness probe. A container without probes is
      ready the moment its process starts, and a pod with such a sidecar takes traffic
      before the sidecar can serve it.
    - **Startup: is it initialised?** It passes once the container can serve: trust
      material loaded and verified, keys found, the listener or socket bound. A native
      sidecar's startup probe gates the start of the main containers, so they never meet a
      missing socket (rule 8).
    - **Readiness: can it serve now?** It follows what the container needs to answer
      correctly: its trust material is current, its keys and its required dependencies
      (store, key service, HSM) answer. A container that is not ready makes its pod leave
      the Service, which is intended: a workload whose sidecar cannot sign must not take
      requests. Saturation is not unreadiness: when every worker or session is busy, the
      dependency is answering, and load must not take replicas out of service (rule 24
      sheds the load instead).
    - **Liveness: is the process stuck?** It passes when the process answers at all,
      whatever the state of its dependencies. A restart does not bring back a store or an
      HSM, and liveness tied to one turns an outage into a restart storm.
    - **Read from state, never from the probe.** A background check asks the dependencies
      at a configured interval and keeps the result; a probe reads it. A probe makes no
      call to a dependency, takes no pooled connection or session, and answers within its
      timeout.
    - **How the kubelet reaches it.** The kubelet presents no client certificate and
      reaches ports only.
      - A container with a network listener serves `grpc.health.v1` to a `grpc` probe, or
        a health path to an `httpGet` probe, on the admin listener (rule 23). That one
        path answers without client authentication and says only serving or not serving:
        no version, no detail, no dependency names. Detail stays behind the admin
        listener's mTLS.
      - A container that listens only on a Unix socket (the sidecars of rule 8) is probed
        by `exec` of its own binary: `<binary> health ready` and `<binary> health live`
        connect to the socket, read its health and exit 0 or 1, with no shell in the image.
        A TCP port opened only for probes is a network listener the sidecar must not have.
    - **One health, in the transport's standard form.** The health that probes read is
      the one clients read: `grpc.health.v1` for gRPC, the health method of a helper's
      protocol, a health path for HTTP. A client of a sidecar can ask the same question
      before it relies on it.
    - **Observable.** Each change of the health state is a log line with its reason and a
      metric (rule 14), so that an outage of a dependency shows as such and not only as
      failed probes in the platform's events.
    - **Tested** (rule 26): with a dependency stopped, the container turns not ready and
      stays alive; with every worker busy, it stays ready; a probe answers within its
      timeout while the dependency hangs.
