# dpop

OAuth 2.0 Demonstrating Proof of Possession, [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449),
for clients that sign proofs and servers that check them. JOSE through
[go-jose](https://github.com/go-jose/go-jose) v4, otherwise the standard library.

| Side | API | RFC 9449 |
|---|---|---|
| client | `Key` (`NewKey`, `NewKeyFromSigner`: the private key as a `crypto.Signer`), `Key.Proof`, `Key.Sign`, `Key.Thumbprint`, `AccessTokenHash` | 4.1, 4.2, 6.1, 7.1, 10 |
| server | `Verifier` (`Config`: algorithms, window, size, `Clock`, `NonceSource`, `ReplayCache`), `Verifier.Verify`, `AccessToken` | 4.3, 6, 7.1, 8, 9, 10, 11.1 |
| responses | `Error`, `WriteTokenError` (authorization server), `Verifier.WriteChallenge` and `Verifier.Challenge` (resource server), `SetNonce` | 5, 7.1, 8, 8.2, 9 |

`Verifier.Verify` performs every check of Section 4.3, each in its own step that cites it, and
with an access token the binding of Section 7.1. [TRACEABILITY.md](TRACEABILITY.md) quotes every
normative statement the package implements and names the tests that prove it; it also lists the
statements that belong to the servers using it.

Decisions an auditor should know:

- **The expected URI comes from the server's configuration** (`Request.URI`), never from the
  `Host` or `X-Forwarded-*` headers a client controls. htu is compared after RFC 3986 syntax- and
  scheme-based normalization, without query and fragment.
- **Algorithms are an allowlist** of registered asymmetric ones, ES256 by default; `none` and MAC
  algorithms cannot be configured. go-jose refuses any other algorithm while parsing.
- **Claims are read by exact name and type**: encoding/json would match `HTU` to `htu`, so the
  payload is read as a map.
- **Time is a parameter**: the package never calls `time.Now`; it reads the `Clock` it is given
  (`SystemClock` in production).
- **Replay detection** stores a SHA-256 of key, htu and jti (Section 11.1). `MemoryReplayCache`
  covers one process and fails closed when full; replicas need a shared `ReplayCache`.
- **Nonces** are a `NonceSource` the server provides (Sections 8, 9); without one, none is
  required.
- **Signing** supports ECDSA P-256/384/521 and Ed25519 keys; RSA proofs can be verified when
  configured, but not created.

```sh
go test ./...                                              # RFC examples, every check, responses
go test -run '^$' -fuzz FuzzVerify -fuzztime 60s .        # also FuzzNormalizeHTU, FuzzAccessToken
DPOP_BLESS=1 go test -run TestTraceability .              # rewrite TRACEABILITY.md after changing the table
```

The known answers come from the RFC itself: the example proofs of Figures 2, 7 and 13 verify at
their own iat, their key's thumbprint is the jkt of Section 6.1, and the access token of Figure 6
hashes to the ath of Figure 14.
