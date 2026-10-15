# Keys and cryptography

## Cryptography is pluggable

Protocol code reaches cryptography only through traits or interfaces a backend
implements, never by calling a crypto library directly. The default backend of each
language is its evaluated standard implementation (see the language profiles); others
(WebCrypto, an HSM, a cloud KMS, a FIPS module) are adapters implementing the same
interfaces, so a core's dependency tree never contains them. Code that must be identical
for every backend (such as the Concat KDF of ECDH-ES) is implemented once over the
backend's primitives, and that is the code that is verified.

## Private keys: the same rules in every language

1. **A private key is a function, never a value.** Code that needs one holds something
   it can ask to sign, decrypt or agree on a key. No API, struct field, config value,
   log line, error, RPC message or test helper outside the key's own implementation
   carries private key bytes, a PKCS#8 or PEM blob, a JWK with `d`, or a PIN.
2. **Hardware-bound keys are the normal case.** Every key API works unchanged for a
   security key (FIDO SK), the Secure Enclave, a TPM 2.0, a smartcard behind a Konnektor,
   an HSM or PKCS#11 token, WebCrypto and a cloud KMS. A software key is one more
   implementation, never the assumption.
3. **Non-exportable.** No operation may require reading, copying, re-encoding or
   zeroizing the private key. A key is a handle, its public key and its capabilities.
4. **The key states its capabilities**: algorithms, whether it signs a digest or the
   whole message, which structures it can sign (a FIDO key signs WebAuthn or SSH
   structures only), whether it needs user interaction. Protocol code chooses from them
   or fails with a clear error; it never falls back silently to a software key or
   another algorithm.
5. **One algorithm per key use.** A key is bound to the algorithm it was configured for;
   a token header, a request or a peer cannot choose another.
6. **Async and cancellable.** Signing can wait for a touch, a PIN, a card or a remote
   service: provide the asynchronous, cancellable form wherever a hardware key may be
   used, honour cancellation and timeouts, and return errors that tell "user cancelled",
   "device absent", "PIN blocked" and "not permitted" apart from a cryptographic failure.
7. **Attestation is verified, not believed.** Where hardware binding matters, the key's
   attestation (TPM, Secure Enclave, FIDO) is checked against the vendor roots; a key's
   claim to be hardware bound is not evidence.
8. **Key bytes live in exactly two places**: software key implementations and the file
   formats that carry keys (PKCS#12, PEM). There they are in buffers that are zeroized
   after use (never kept in immutable strings), parsed at the edge (the command, the
   CLI), and turned into a key object at once.
9. **Keys do not cross process boundaries.** The process that owns a key signs with it;
   another process sends data to sign and receives signatures (as `epa` does with `ti`).
10. **Platform glue is an adapter.** Security.framework, TPM access, CTAP/HID, PKCS#11,
    Konnektor calls live in adapter units implementing the key interface, never in a
    core, and follow the dependency rules and the [interop](../interop.md) rules (no
    native library linked into a server process).

Each language profile maps these rules to its types (signer, key agreement, decrypter,
capabilities, software key) in one table.

## Hardware-bound keys

Hardware-bound keys are first-class, behind the same abstraction: security keys (FIDO
SK), the Secure Enclave, TPM 2.0, smartcards (SMC-B, HBA, eGK via a Konnektor), HSMs and
cloud KMS. What they share, and what the abstraction therefore must not assume away:

- **Not exportable.** There is no private key to read, copy, serialise or zeroize; the
  key is a handle and the public key. No API may need more.
- **Algorithms are the device's.** The Secure Enclave and most TPMs sign P-256 only (TPMs
  also RSA, some P-384); security keys P-256 and Ed25519; brainpool only smartcards and
  HSMs. A key reports what it can do, and protocol code picks from that set or fails
  with a clear error; it never falls back to a software key.
- **Digest or message.** The Secure Enclave and TPMs sign a digest, Ed25519 and some
  HSM mechanisms the whole message. The signer interface says which it takes, and the
  hashing for prehashed keys happens once, in shared code.
- **Not every key signs arbitrary data.** A FIDO security key signs WebAuthn or SSH
  structures (authenticator data with a client-data hash), not raw messages; it can
  serve protocols built for it (WebAuthn, SSH), not a plain JWS. The abstraction exposes
  this instead of hiding it.
- **Slow, asynchronous and interactive.** A signature can wait for a touch, a PIN, a
  biometric or a card in a reader, and can be cancelled or time out. Signing is
  asynchronous and cancellable, and errors distinguish "user cancelled", "device
  absent", "PIN blocked" and "not permitted" from cryptographic failure.
- **Attestation.** Where the device provides it (TPM, Secure Enclave via App Attest or
  DeviceCheck, FIDO), the key can present attestation of where it lives; protocols that
  rely on hardware binding verify it and do not trust a claim.
- **Platform glue stays at the edge.** Enclave, TPM and FIDO access needs platform APIs
  (Security.framework, TSS or the kernel's TPM device, CTAP over HID); each is an
  adapter implementing the key interface, never a dependency of a core.

## Secrets and randomness

- Secret material lives in zeroizing buffers; digests and MACs are compared in constant
  time.
- Randomness comes from the operating system's CSPRNG through the crypto backend:
  identifiers, `state`, nonces and codes alike. No time-ordered identifiers where an
  attacker could learn from them.
- Signature verification and other operations on public data use the evaluated standard
  implementation; custom constant-time code exists only for secret operations where no
  evaluated implementation does, and is then formally verified
  ([dependencies](../conventions/dependencies.md), [testing](testing.md)).
