# Release Notes

# Release go/dpop v1.0.0-beta.1

A rewrite against [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) on go-jose v4; the first
release with a stable API in view. `TRACEABILITY.md` maps every normative statement the module
implements to the tests that prove it.

### breaking
- New API. Client: `Key` (`NewKey`, `NewKeyFromSigner` over a `crypto.Signer`), `Key.Proof`,
  `Key.Sign`, `Key.Thumbprint`, `AccessTokenHash`. Server: `Verifier` (`NewVerifier`, `Config`),
  `Verifier.Verify(header, Request)`, `AccessToken`, `Error` with `WriteTokenError`,
  `Verifier.WriteChallenge`, `Verifier.Challenge`, `SetNonce`. `PrivateKey`, `FromJWK`,
  `NewBuilder`, `DPoP`, `Parse`, `ParseRequest`, `ParseOptions`, `SignRequest`, `DPoPError`,
  `CalculateAccessTokenHash` and `DPoPHeaderName` are gone.
- The expected URI is the server's own (`Request.URI`); `Host` and `X-Forwarded-Proto` are no
  longer used to rebuild it.

### features
- Every check of Section 4.3: one DPoP header, a single token68 JWT, required claims read by
  exact name and type, `typ` `dpop+jwt`, an allowlist of asymmetric algorithms (`none` and MAC
  cannot be configured), signature by the embedded `jwk`, no private key in it, `htm`, `htu`
  after RFC 3986 normalization without query and fragment, the server nonce, the `iat` window
  in both directions, `ath` and the key binding of the access token.
- Grant binding by thumbprint (`dpop_jkt`, Section 10); replay detection through a
  `ReplayCache` keyed by a SHA-256 of key, `htu` and `jti` (Section 11.1), with a bounded
  `MemoryReplayCache` that fails closed; server nonces through a `NonceSource` (Sections 8, 9).
- Responses as the RFC prescribes: 400 with an RFC 6749 error body and `DPoP-Nonce` for
  authorization servers, 401 with a `WWW-Authenticate: DPoP` challenge carrying `algs` for
  resource servers, uncacheable when a nonce is sent.
- Proofs signed through `crypto.Signer` with ECDSA P-256/384/521 and Ed25519 keys; `jti` from
  130 random bits.
- Time from a `Clock`; the module never reads the system clock itself.
- Known-answer tests from the RFC's own examples (Figures 2, 7, 13, 14; the `jkt` of Section
  6.1), one test per check, fuzz targets for the verifier, URI normalization and credentials.

### changed
- Dependencies: go-jose v4 only; lestrrat-go/jwx and its modules are gone.

# Release go/brainpool v1.2.0

### breaking
- `josebp.JWT.HeadersJson` and `PayloadJson` are renamed to `HeadersJSON` and `PayloadJSON`;
  `josebp.JSONWebKey.Algortihm` is renamed to `Algorithm`. The JSON encoding of a JWK is unchanged.

### fixed
- `josebp.ParseToken` with `WithKey` no longer panics on a signature that is shorter than the
  curve requires; a signature of the wrong length is an error.

### changed
- Tests use the standard library only; testify, and with it go.yaml.in/yaml/v3, is no longer a
  dependency.
- Clean under the workspace golangci-lint configuration; doc comments for the exported josebp API.
- update golang.org/x/crypto to v0.58.0

# Release go/pkcs12 v0.100.0

### features
- `legacy.Decode` reads BER-encoded files and RC2-40/128, two-key Triple DES and DES-EDE3-CBC
  in PBES2 in pure Go; no OpenSSL subprocess any more. New subpackages `legacy/ber` (BER to DER)
  and `legacy/rc2` (RFC 2268).
- `ErrLimitExceeded`: iteration counts above 10,000,000 are refused before any key derivation.
- MAC with SHA-224; friendly names with UTF-16 surrogate pairs; passwords outside the BMP
  encoded as surrogate pairs, as OpenSSL and Java do.
- Language-neutral specification, generated conformance corpus and interoperability matrix in
  `spec/pkcs12`.

### fixed
- An unknown PBKDF2 PRF fails with `ErrUnsupportedAlgorithm` instead of falling back to SHA-1.
- `EncodeWithOptions` no longer modifies the caller's options, honours `CertEncryption`
  (certificates are now encrypted by default, as OpenSSL does) and writes `hmacWithSHA*` as
  PBKDF2 PRF instead of the digest OID. Files written by earlier versions stay readable.
- Trailing data, unsupported public-key modes and unknown safe content types are rejected
  instead of ignored.

### changed
- `legacy.ConvertWithOpenSSL` is deprecated and converts in Go.
- Test fixtures with private keys removed; keys are generated per test run.
- License headers in every source file.
- update golang.org/x/crypto to v0.58.0

This lab project ist yet to yield a first release. Stay tuned!

**Every module — library and command — is versioned solely by its own git tag**
`go/<module>/vX.Y.Z`, bumped only when that module changes. There is no shared version and
no version variables. See the [Development & Release Guide](./go/docs/development.md) for the
step-by-step workflow.

### Local development (go.work)

The tracked `go.work` workspace resolves every in-repo module from its local source. Edit any
library (e.g. `brainpool`) and the change is immediately used by every command (e.g. `zero-epa`)
when you build, test, or run inside the workspace — no tags, no go.mod edits.

### Versions come from git tags

Each module's version is its latest `go/<module>/vX.Y.Z` tag. `go install <cmd>@vX.Y.Z`
reports its version automatically (Go embeds the module version in the build info); local
and Docker builds stamp it from `git describe` (clean `0.20.2` on a tag, `0.20.2-3-g…` past
it, `dev` when untagged). Manage with `just versions`, `just changed`, and
`just tag <module> <version>`.

Commands are installable directly (the `@` takes the bare semver; Go maps the `go/<mod>`
subdirectory to the tag):

```
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@v0.20.2
go install github.com/gematik/zero-lab/go/pdp/cmd/zero-pdp@v0.22.2
```

The `ti` command-line tool is the Rust one (`rust/ti-cli`, `cd rust && just install`); the
Go `ti` and `kon` modules are archived at `go/ti/v0.23.4` and `go/kon/v0.21.4`. `gempki` is archived at `go/gempki/v0.23.1`; its successor is the Rust `ti-pki`, and the tag keeps it `go get`-able for external consumers.

`zero-caddy` combines its version with the upstream Caddy version as SemVer build metadata,
e.g. the binary reports `zero-caddy 0.20.2+caddy2.11.4` and the Docker image is tagged
`zero-caddy:0.20.2-caddy2.11.4` (`+` is illegal in Docker tags).

### Releasing a change

A tagged build (`go install`, tag-pinned Docker) runs **outside** the workspace, so a command
resolves libraries from its `go.mod`. To make a tagged build pick up a library change:

1. Edit the library; build/test/run locally (go.work uses it directly).
2. Commit and **push** the change.
3. `just sync` — repins every in-repo `require` to the branch tip (records the pushed
   commits' pseudo-versions). Commit and push the `go.mod`/`go.sum` updates.
4. `just tag <module> <version>` for each changed module (use `just changed`), then
   `just push-tags`.
5. `go install …/<cmd>@<tag>` now builds the command at its tag with the updated library code.

`just tidy` only syncs `go.mod`/`go.sum` to imports (no version changes). `just upgrade`
deliberately bumps external dependencies; after running it, re-run `just sync` before tagging.

If `proxy.golang.org` 404s a freshly pushed tag (negative cache), set
`go env -w GOPRIVATE=github.com/gematik/zero-lab` to install via direct VCS fetch.
