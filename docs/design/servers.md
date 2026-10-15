# Servers

The same rules bind server software in every language: everything deployed as a Docker
(OCI) workload, today `zero-pdp`, `zero-pep-proxy`, `zero-caddy`, `zero-bff-pdp`,
`zero-epa` and `metsubushi`, and any to come, together with everything that runs inside
such a workload. `ti serve` is not a workload of its own, but it can run as a sidecar in
one; there it is part of that workload and follows these rules. Client-side software
(the `ti` CLI, `ti serve` next to a client, the bindings in apps) follows the other
documents. Server software is built to run as a confidential workload: in an enclave,
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
   containers: SEV-SNP, TDX, Nitro, confidential Kubernetes). Inside: one static binary
   (no native library linked in, [interop](../interop.md)), a `scratch` or distroless image without shell or package manager, the
   fewest dependencies ([dependencies](../conventions/dependencies.md)). The host, the hypervisor operator, the Kubernetes
   control plane, the ingress and sidecars outside the enclave are not trusted.
5. **All data is encrypted outside the workload.** TLS ends inside the workload, not at
   an ingress or sidecar outside the TCB. Data at rest in `kv`, Redis, Postgres, files or
   backups is encrypted and authenticated by the workload (AEAD, with the record's key,
   tenant and type as associated data, so records cannot be swapped or replayed into
   another context); the store sees ciphertext only. Logs, metrics and traces carry no
   personal data, tokens or secrets.
6. **Key provisioning bound to attestation.** Keys and secrets are released to a workload
   only after its attestation is verified (a KMS or key broker with a release policy on
   the measurement), delivered as files (`*_PATH`), never baked into images, environment
   variables or the kv store. Workload keys follow the [private-key rules](keys.md); rotation
   works without a restart; credentials are short-lived where the peer allows.
7. **Attestation friendly, signed workloads.** Builds are reproducible (pinned toolchain,
   base images by digest, `-trimpath`, no build-time network for code), images are
   signed with provenance and an SBOM, and the measured image contains everything that
   runs: no code or plugins loaded at runtime. Configuration that changes behaviour is
   part of the measurement or hashed and reported. A workload exposes its version and
   build digest, and verifies the attestation of peers where hardware binding matters.
8. **Kubernetes, Docker and sidecars as untrusted neighbours.** Run as non-root with a
   read-only root filesystem, no capabilities, seccomp `RuntimeDefault`, resource limits;
   liveness and readiness reflect real state (trust material loaded, storage reachable);
   SIGTERM drains and shuts down gracefully; configuration and trust material reload from
   mounted files. A sidecar (`ti serve`, a key broker agent) is reached over a Unix socket
   with file permissions; a sidecar outside the enclave gets only ciphertext or data that
   is public anyway.
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
    - Rate, errors and duration per endpoint and per dependency (store, key service, `ti
      serve` sidecar, upstream IdPs), saturation per replica; SLOs per service with
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
    or a dependency they need means deny, never allow. Degraded modes are explicit and
    bounded (stale trust material only within its policy limits), never a silent
    default to permissive.
17. **Refuse to start with insecure configuration.** At start-up a production server
    validates its whole configuration and exits on a TEST-ONLY anchor, an in-memory
    store, disabled verification, a missing key, a relaxed policy or a debug endpoint,
    as `TrustConfig::validate(Tier::Prod)` does for trust material. Test-only code and
    material are not compiled into production builds (build features or tags; the
    language profiles name them).
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
    operational logging pipeline.
22. **Mixed versions work.** During a rolling deploy versions N and N+1 run side by side:
    tokens, sealed values, stored records and messages from either are readable by the
    other; schema changes go expand, migrate, contract; keys rotate with an overlap in
    which old and new both verify.
23. **A separate admin plane.** Admin, metrics, health and debug endpoints listen on their
    own port with their own authentication (mTLS), restricted by NetworkPolicy; nothing
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
    and dynamic scanning (OWASP ZAP or equivalent) of every exposed endpoint.
