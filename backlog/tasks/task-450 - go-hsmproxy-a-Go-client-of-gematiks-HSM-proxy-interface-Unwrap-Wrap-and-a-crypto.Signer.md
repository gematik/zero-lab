---
id: TASK-450
title: >-
  go/hsmproxy: a Go client of gematik's HSM proxy interface: Unwrap, Wrap and a
  crypto.Signer
status: To Do
assignee: []
created_date: '2026-11-27 12:30'
labels:
  - go
  - security
  - keys
dependencies: []
priority: medium
ordinal: 458000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by zeta-authserver-go TASK-141 (2026-11-27): the authorization server is to unwrap its keychain (kv.Unwrapper) and sign its tokens (crypto.Signer) through the HSM proxy (gemSpec_ZETA V2.0.0_CC A_28826, A_28863, A_28829), and zeta-admin-tools to wrap new keychain entries through it. Both are Go; the sidecar is rust/ti-hsm-proxy (TASK-389). One client serves both.

- Methods whose shapes are the consumers' small interfaces, so that nothing imports another for them: Unwrap(ctx, kekID string, iv, ciphertext, tag, associatedData []byte) ([]byte, error) is kv.Unwrapper (Decrypt); Wrap(ctx, kekID string, plaintext, associatedData []byte) (iv, ciphertext, tag []byte, err error) is Encrypt; Signer(ctx, keyID) returns a crypto.Signer over GetPublicKey and Sign (digest with algorithm NONE, P1363 returned as ASN.1 DER as crypto.Signer has it); a health probe.
- Transport of servers.md rule 29: a Unix socket, TCP with TLS or mTLS (A_28830: components authenticated by mTLS), plaintext only where the operator accepts it.
- Generated protobuf/gRPC code is allowed (it carries no licence header); the dependency it brings is weighed against gRPC over net/http by hand (HTTP/2 over the socket with Transport.Protocols, the six messages with protowire), since it lands in every binary that imports the module.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Unwrap, Wrap and Signer against rust/ti-hsm-proxy in its simulator mode, in CI, with associated data and a key_id of A_28831's scheme
- [ ] #2 A value of the client's type is a kv.Unwrapper and its Signer a crypto.Signer, shown by a compile-time assertion in a test, without the module importing kv
- [ ] #3 Unix socket, TLS, mTLS and accepted plaintext as rule 29 has them; a refusal of the proxy is an error naming the operation and key_id, never the data
<!-- AC:END -->
