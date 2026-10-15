# PKCS#12: conformance

How an implementation of [README.md](README.md) proves conformance: the corpus and its manifest, the
generator, the command-line contract every decoder provides, and the interoperability matrix.

## Layout

```text
testdata/
  manifest.json      every case: source, profile, rules covered, expected result
  vendor/            two connector client identities as delivered (BER, RC2-40, 3DES,
                     SHA-1 MAC), with their passwords and SHA256SUMS
tool/                p12conformance: generates the corpus, verifies decoders (Go, stdlib only)
interop/
  run.sh             generates a corpus and runs every available decoder
  go/ rust/ openssl/ python/ java/   one adapter per decoder
  matrix.md          result of the last run
```

## Corpus

The corpus is **generated per run** and not committed: keys and certificates are created fresh by
the generator (P-256 CA, RSA-2048 and P-256 leaves, all `TEST-ONLY`), and `openssl pkcs12 -export`
writes the files from them. No private key of the corpus is ever committed. The only committed
files are the two vendor identities in `testdata/vendor`, which no tool can regenerate.

Each case is written once per encoding:

| Encoding | Meaning |
|---|---|
| `der` | as OpenSSL wrote it |
| `ber` | the same file with every constructed element in indefinite-length form and every OCTET STRING longer than 512 bytes split into constructed segments. Only the outer encoding changes; the values of all OCTET STRINGs stay byte for byte, so MACs and digests stay valid (P12-011). Always profile `legacy`. |
| `as-is` | a committed file, unchanged |

Negative cases mutate the produced file: `truncate`, `append` a byte, `flip` one bit at an offset
from the end (inside the authSafe), `patch` an OID in place, or rewrite the MAC iterations
(`mac-iterations`; MacData lies outside the MAC, so the rest stays valid).

## Manifest

`testdata/manifest.json`:

```json
{
  "id": "legacy-rc2-40-3des",
  "description": "OpenSSL -legacy: certificates with pbeWithSHAAnd40BitRC2-CBC, ...",
  "rules": ["P12-033", "P12-013", "P12-020"],
  "profile": "legacy",
  "openssl": ["-legacy"],
  "key": "rsa",
  "chain": true,
  "password": "test",
  "encodings": ["der", "ber"],
  "expect": {"code": "ok", "certificates": ["leaf", "ca"], "keys": ["leaf"], "pairs": 1, "mac": "sha1"}
}
```

| Field | Meaning |
|---|---|
| `openssl` / `file` / `raw` | source: arguments for `openssl pkcs12 -export`, a file under `testdata/`, or `random` / `pem` |
| `key`, `chain` | leaf key type (`rsa`, `ec`); `chain` adds the CA certificate (`-certfile`) |
| `password`, `password_file` | password the file is written with; `decode_password` overrides it for decoding |
| `mutation` | see Corpus |
| `expect.code` / `expect.codes` | the result code, or the codes of which any is conformant |
| `expect.certificates`, `expect.keys` | symbolic contents (`leaf`, `ca`), resolved to SHA-256 digests by the generator |
| `expect.certificates_sha256`, `keys_sha256`, `keys_public_key_sha256` | literal digests for committed files |
| `expect.pairs`, `expect.mac`, `expect.friendly_names` | number of pairs, MAC digest name or `null`, friendly names by symbol (`leaf`, `leaf-key`, `ca`) or digest |

`p12conformance generate` writes, next to the files, `expected.json`: one entry per case and
encoding with file name, password file, profile, allowed codes and the expected result in the form
of the command-line contract.

## Command-line contract

Every decoder provides an adapter the harness calls once per file:

```console
decoder decode --password-file FILE.password FILE.p12
```

The password file holds the password octets, without trailing newline. The adapter writes exactly
one JSON object to stdout and exits 0 whatever the verdict; a non-zero exit means it could not run.

```json
{
  "code": "ok",
  "detail": "",
  "certificates": [{"sha256": "…", "friendly_name": "…", "local_key_id": "…"}],
  "keys": [{"sha256": "…", "public_key_sha256": "…", "friendly_name": "…"}],
  "pairs": [[0, 0]],
  "mac": "sha256"
}
```

| Field | Meaning |
|---|---|
| `code` | a [result code](README.md#result-codes); `error` for decoders that report no reason |
| `certificates[].sha256` | SHA-256 of the certificate DER, hex |
| `keys[].sha256` | SHA-256 of the PKCS#8 PrivateKeyInfo DER as decrypted |
| `keys[].public_key_sha256` | SHA-256 of the key's SubjectPublicKeyInfo DER; for decoders that re-encode keys |
| `pairs` | `[certificate index, key index]` per pair (P12-045) |
| `mac` | `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, or `null` without MacData |

## Verification

```console
cd tool
go run . generate -manifest ../testdata/manifest.json -out /tmp/corpus
go run . verify -corpus /tmp/corpus [-profile modern] [-coarse] -- DECODER [ARGS...]
```

- Contents are compared as multisets: certificates by digest, keys by PKCS#8 or public-key digest;
  expected friendly names must match; the number of pairs must match.
- *Full* comparison also requires the exact result code and the MAC digest. *Coarse* comparison
  (`-coarse`) checks success versus failure only, for decoders that report no reason.
- `-profile modern` skips the cases of profile `legacy`.
- Each case has a time limit (`-timeout`, default 30 s).

A decoder is **conformant** for its profile when every case of that profile passes with full
comparison.

## Implementations

| Decoder | Profile | Adapter |
|---|---|---|
| `go/pkcs12` `pkcs12.Decode` | modern | `interop/go` |
| `go/pkcs12/legacy` `legacy.Decode` | legacy | `interop/go -legacy` |
| `rust/ti-pkcs12` | legacy | `interop/rust` |
| OpenSSL CLI | measured, coarse | `interop/openssl` |
| pyca/cryptography | measured, coarse | `interop/python` |
| JDK `KeyStore` PKCS12 | measured, coarse | `interop/java` |

The Go tests generate the corpus and run it in-process (`go/pkcs12/internal/conformance`).

## Interoperability matrix

`interop/run.sh` builds every adapter whose toolchain is installed, generates a fresh corpus, runs
all decoders and writes [interop/matrix.md](interop/matrix.md). Differences of third-party
libraries are recorded there as found, not worked around.

### Differences found in third-party decoders

As of the run recorded in `interop/matrix.md`:

| Decoder | Cases | Difference |
|---|---|---|
| OpenSSL 4.0 CLI, pyca/cryptography 50, JDK 21 | `trailing-byte` | accept bytes after the PFX (P12-003) |
| OpenSSL 4.0 CLI, pyca/cryptography 50 | `mac-iterations-limit` | no iteration limit, run into the timeout (P12-036) |
| pyca/cryptography 50 | `friendly-names`, `vendor-*` | reports no friendly name for keys (API limitation) |
| JDK 21 | `pbes2-aes192`, `pbes2-des-ede3`, `legacy-rc2-128-2des` | rejects AES-192 and DES-EDE3 in PBES2, RC2-128 and two-key Triple DES |
| JDK 21 | `unicode-password` | rejects a password with a character outside the BMP |
| JDK 21 | `certificates-only`, `plain-bags`, `key-only` | loads certificates without key only with Oracle's trustedKeyUsage attribute, and keys only with a certificate |
| JDK 21 | `friendly-names` | lower-cases friendly names (aliases) |
