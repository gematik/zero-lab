# Principles

## This is security-critical software

zero-lab builds trust decisions for the German Telematikinfrastruktur: PKI path
validation, TSL verification, OCSP, JOSE, IDP authentication, smartcard and Konnektor
access, ePA VAU. A defect here can accept a forged certificate, leak key material or let
an attacker in. Treat every change accordingly: correctness and security before
convenience, features or speed of delivery.

## Every change is held against these criteria

The criteria bind all development, in every language. Check a plan against them before
writing it and the change before calling it done; a change that falls short of one says
so and why, or does not land. Each criterion is detailed in the document it links to; the
language profiles ([Rust](../rust/docs/design.md), [Go](../go/docs/design.md)) say how
their code meets it.

1. **Sans I/O:** cores do no network, file or clock access of their own
   ([architecture](architecture.md#sans-io)).
2. **Transport independent, trust in the core:** HTTP and other transports come from the
   host through a small interface, with no client in a core; certificate and TLS peer
   verification follow the core's rules through a verifier the host must use
   ([architecture](architecture.md#the-host-owns-the-transport-the-core-owns-trust)).
3. **Portable:** cores run wherever a host does, including the browser (WebAssembly) and
   constrained environments ([architecture](architecture.md#portability)).
4. **Trust from verification only:** where bytes came from never makes them trusted;
   signatures and the anchor decide ([architecture](architecture.md#trust-from-verification-only)).
5. **Pluggable crypto, private keys as functions, hardware-bound keys supported**
   ([keys](design/keys.md)).
6. **Testable logic** ([testing](design/testing.md#testable-logic)).
7. **Verified, not only tested:** formal verification where we write subtle code
   ourselves, and the language's safety and security tooling as part of the build
   ([testing](design/testing.md#verification-and-tooling)).
8. **Few, stable, maintained, evaluated dependencies**
   ([dependencies](conventions/dependencies.md)).
9. **Fuzzed:** every reader of attacker-chosen bytes has a fuzz target
   ([testing](design/testing.md#fuzzing)).
10. **Servers are confidential workloads:** transport independent, OWASP baseline,
    horizontally scalable, minimal TCB in an enclave, data encrypted outside the
    workload, keys provisioned on attestation, signed and reproducible, cloud native,
    stateless by cryptography first and ACID for the state that remains, caches never
    trusted, multi-zone, observable without leaking, hardened protocol profiles, fail
    closed, insecure configuration refused, business APIs to the gematik API rules,
    per-tenant keys, privacy by design, audit trail, mixed versions, admin plane apart,
    resilient, signatures enforced at deploy time, tested as a server
    ([servers](design/servers.md)).
11. **Languages meet through processes or shared specifications:** a server process does
    not link another language's native core; functions implemented twice share one
    specification ([interop](interop.md)).

Gaps the code still has against these criteria are backlog tasks; work on a crate or
module closes its gaps rather than adding to them, and a new gap becomes a task.
