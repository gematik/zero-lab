# ti-hsm

Keys in a hardware security module, reached over PKCS#11 alone: the way to the key of the key
provider sidecar a workload of the gematik Telematikinfrastruktur (TI) uses for a key in an HSM
([servers](../../docs/design/servers.md), rule 6). It loads the PKCS#11 module it is given, so a
software token in development and a vendor's module in production get the same calls.

What exists is the first step of TASK-389, a spike: a PKCS#11 adapter (`Module`, `Token`) that
finds or makes keys by label and signs (ECDSA over a digest or a message) and encrypts and
decrypts (AES-256-GCM with associated data), driven through SoftHSM2 by a gated suite. Every key
is made on the token, sensitive, not extractable and for its one use. What the token did is in
[docs/spike-softhsm2.md](docs/spike-softhsm2.md).

Not yet here: the gRPC interface of the HSM proxy, the sidecar binary, a vendor's module.

```console
just hsm-spike    # SoftHSM2 2.7 or later, or TI_HSM_PKCS11_MODULE_PATH
```

`publish = false`; the crate is not released.
