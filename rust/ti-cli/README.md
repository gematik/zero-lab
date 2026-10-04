# ti-cli

`ti`, the command-line tool for the gematik Telematikinfrastruktur (TI), in Rust, built
on [`ti-pki`](../ti-pki) and [`ti-connector-client`](../ti-connector-client). Commands are
grouped by subsystem: `pki` and `connector`.

```sh
just install                        # cargo install into ~/.cargo/bin
just install-fast                   # a quicker build for testing, same place
ti pki inspect card.pem             # what the TI reads from a certificate
ti pki inspect - < card.der
ti pki inspect identity.p12         # PKCS#12; password 00 unless --p12-password
ti pki inspect card.pem > card.md   # piped output is Markdown, with the PEM
ti --format json pki inspect card.pem | jq '.certificates[0].certificate_type'
ti pki profiles list
ti pki profiles describe smb-aut
ti pki profiles describe smb-aut --env ref   # and the TSL CAs that may issue its types
ti pki verify card.pem              # exit 0 valid, 1 not valid
ti pki verify smcb.p12              # the certificate with its key is the end entity
ti pki pkcs12 convert old.p12 new.p12   # DER, PBES2 AES-256, SHA-256 MAC; mode 0600
ti pki verify card.pem --offline    # cached trust material, no OCSP
ti pki verify --connect epa-as-1.ref.epa4all.de   # a TLS server's chain, its name as --fqdn
ti pki roots list --env ref         # the roots reached from the anchor
ti pki tsl show                     # the TSL's CAs under the roots that signed them
ti pki tsl show --rejected          # the CAs no verified root signed, and why
ti pki tsl show --ca SMCB-CA51      # one CA; Markdown adds its PEM
ti pki tsl verify ECC-RSA_TSL.xml   # signature, signer, signer OCSP; exit 0 valid
ti connector configs                # the .kon files, shared with the Go ti
ti connector use praxis             # the configuration later commands use
ti connector get cards
ti connector get certificates 80276883110000163974   # ICCSN, Telematik-ID or handle
ti connector describe certificate 1-SMC-B-Testkarte-883110000129072 C.AUT
ti connector verify pin 80276883110000163974         # at the card terminal; exit 0/1
ti connector sign letter.txt --card 80276883110000163974  # CAdES → letter.txt.p7s
ti connector sign report.pdf --card 80276883110000163974  # PDF/A → report.signed.pdf (PAdES)
ti connector verify signature letter.txt --signature letter.txt.p7s
ti connector encrypt letter.txt --to recipient.pem      # → letter.txt.p7m
ti connector encrypt letter.txt --to-card 80276883110000162094   # for a card's C.ENC
ti connector export certificate 80276883110000162094 C.ENC > enc.pem
ti connector decrypt letter.txt.p7m --card 80276883110000163974
ti connector comfort activate 80276883110000163974   # PIN.QES once, then signatures without
ti probe ref                        # which TI services of ref answer, live (or --env ref)
ti cache clear
ti schema pki verify                # JSON Schema of a command's output
ti agent                            # usage guide for scripts and agents
ti version
```

`just cli-targets` builds release binaries into `target/dist` for Linux x86_64 (static
musl), Windows x86_64 and, on a Mac, macOS on Apple silicon: the foreign ones through
[cross](https://github.com/cross-rs/cross) in Docker.

Shell completion comes from the binary itself, so it always matches its commands:

```sh
ti completions zsh > ~/.zfunc/_ti                       # zsh (with fpath+=~/.zfunc)
ti completions bash > ~/.local/share/bash-completion/completions/ti
ti completions fish > ~/.config/fish/completions/ti.fish
ti completions powershell >> $PROFILE                   # also: elvish
```

## Install

Releases are on [GitHub](https://github.com/gematik/zero-lab/releases), tagged
`rust/ti-cli/vX.Y.Z`, with a binary for macOS on Apple silicon, Linux x86_64 (static)
and Windows x86_64.

- **Homebrew** (macOS, Linux): `brew install spilikin/tap/ti`; `brew upgrade ti`
  updates, `brew autoupdate` keeps it current. `ti` itself never checks for updates.
- **Download:** take the binary for your platform with `SHA256SUMS`, then check it:

  ```sh
  shasum -a 256 -c SHA256SUMS --ignore-missing
  chmod +x ti-*-* && mv ti-X.Y.Z-<target> ~/.local/bin/ti
  ```

- **From source:** `cargo install --locked --git https://github.com/gematik/zero-lab --tag
  rust/ti-cli/vX.Y.Z ti-cli`, or `just install` in a checkout.

## Trust material

`pki roots list` and `pki tsl show` show what `verify` works with, for one environment
(`--env`, default `prod`; there is nothing to detect from here, so `TI_ENV=auto` means
`prod` and `--env auto` is an error). `roots list` gives the
roots the A_28419 walk reaches from the embedded anchor. `tsl show` lists the TSL's CAs
with the verified root that signed each, or in red why none did. Filter with `--ca`,
`--provider`, `--root` and `--rejected`.

The TSL is verified wherever it is loaded (`spec/tsl-xmldsig`): signature, signer under
the embedded TSL signer CA, `NextUpdate`, the list seen before (kept in the state
directory, so an older list stays rejected), and online the signer's OCSP status;
offline or with `--at` the trust line says the status was not checked. A list that
fails is not used at all. Of each entry the view shows only what the CA certificate says
(name, organization, validity) and which verified root signed it; the TSL's per-CA
metadata (provider names, certificate types per CA) is never shown as fact. The provider
name is in the JSON, for filtering. `--offline` works from the cache; `--at` shows the
material as of another time.

`pki tsl verify FILE` checks a TSL file: its XMLDSig/XAdES signature, a C.TSL.SIG
signer issued by the embedded TSL signer CA (GEM.TSL-CA3 in production, GEM.TSL-CA28
TEST-ONLY elsewhere), `NextUpdate` with `--grace DAYS` (default 0), and the signer's OCSP
status unless `--offline` or `--at`. `--previous OLD.xml` requires another `Id` and a
greater sequence number, or the same list. `--env auto`, the default, takes the
environment whose TSL signer CA issued the signer; `--env prod` accepts a production TSL
only. An invalid list is exit 1 with the gemSpec_PKI result code and the rule of
`spec/tsl-xmldsig` that failed; entries that cannot be processed are skipped and
listed.

## Verify

`ti pki verify` builds the chain to the TI roots through the CAs of the TSL and
validates it: RFC 5280 path, gemSpec_Krypt key, the requirements of the profile
(`--profile auto|none|<name>`), and OCSP for the end entity and every CA below the root.
The environment comes from `--env` (`TI_ENV`) or, with `auto`, from the certificates:
production only on evidence from the production roots, otherwise ref. `--at` validates
at another time (OCSP still answers for now).

roots.json and the TSL are downloaded from the environment's URLs and verified by
`ti-pki` against the embedded anchor; a CA from the TSL counts only if a verified root
signed it. Where they came from does not matter, so the cache is as untrusted as the
network. The revocation line reports the outcome over the chain (`not revoked`,
`revoked`, `unknown`, `incomplete`); `revocation_mode` in JSON names the policy.

`--offline` makes no request: it uses the cached material, or the embedded roots
without a TSL when nothing usable is cached (then pass the issuing CA with `--issuer`),
and does not check revocation. The report says so (`"revocation_checked": false`).

## Connector

`ti connector` talks to a Konnektor as the Go `ti connector` does, with the same `.kon`
files: `-c NAME|PATH` or `TI_CONNECTOR_CONFIG`, else the one `connector use` selected,
else `default`; names are looked up here and in `~/.config/telematik/connectors/`.
`${NAME}` in a `.kon` file is expanded only in the credentials, so a file from someone
else cannot send environment variables to a foreign host. Calls time out after
`--connector-timeout` (10 s), calls that wait for the card terminal after
`--card-timeout` (300 s); `-v` prints one line per call, `-vv` the SOAP bodies. SMC-KT,
KVK and eGK are restricted on the Konnektor's SOAP API; calls about them fail with an
explanation. While a PIN is entered, a terminal shows a spinner on stderr, a busy
tab (OSC 9;4: Ghostty, iTerm2, Windows Terminal, cmux) and one desktop notification (OSC
9). PKCS#12 client certificates must be P-256, P-384 or RSA for now (TLS runs
on ring, which has no brainpool). Comfort signature keeps each session's random user ID
owner-only in `~/.local/state/telematik/ti/comfort/` until a secure store replaces it.

## Conventions

The tool is meant for people and for agents alike:

- Results go to stdout, diagnostics (`-v`, `-vv`) and errors to stderr.
- `--format auto|text|markdown|json` (or `TI_FORMAT`). `auto` gives aligned, colored text
  on a terminal and Markdown when piped: readable in notes, chats and by agents.
  The terminal view is sectioned and complete (Subject, Issuer, Validity, …; Result,
  Chain, Errors). Lists of objects (cards, roots, CAs, profiles, …) are tables with the
  focus column first, on the terminal and in Markdown; see "CLI output" in
  [docs/development.md](../docs/development.md) for the columns of each. Markdown is
  otherwise compact, with certificates as fenced PEM blocks, which the terminal view
  leaves out.
- `json` writes one document with a `"schema"` version; fields are only added within a
  schema version. Certificates are in `pem` fields. `ti schema [COMMAND]` prints the
  JSON Schema of each command's output (kept in `schemas/`, checked against real output
  by the tests), and `ti agent` prints [AGENTS.md](AGENTS.md), the guide for scripts
  and agents. Errors in JSON mode are `{"schema":1,"error":{"kind","message","hint"}}`
  on stderr.
- Times in text and Markdown are in the system time zone: `2023-02-09 00:00 CET` for a
  single instant, the date alone in lists (`TZ` is honoured). JSON keeps RFC 3339 in UTC.
- Colors and JSON highlighting only on a terminal; `--color`, `NO_COLOR` and
  `CLICOLOR_FORCE` override. Long lines are never cut; the terminal wraps them.
- Never interactive. Every input is a flag, an environment variable, a file or stdin.
- Exit codes: `0` success (or: the certificate is valid), `1` not valid, `2` usage,
  `3` trust material unavailable, `4` input unreadable, `5` output failed.

## Files

State shared by TI tools lives in one `telematik` folder, in the XDG layout on every
Unix including macOS:

| | Linux, macOS | Windows |
| --- | --- | --- |
| Cache | `$XDG_CACHE_HOME/telematik/ti` (`~/.cache/telematik/ti`) | `%LOCALAPPDATA%\telematik\ti` |

`--cache-dir` or `TI_CACHE_DIR` override it. Downloaded trust material lives below it
in `ti-pki/v1/{roots,tsl}/<id>.body` with its HTTP validators in `<id>.json`, `<id>`
derived from the URL. An entry is used without asking for an hour, then revalidated
with its `ETag`; when the network fails it serves for up to a day more. Material older
than 24 hours (production) or 7 days (elsewhere) is not used.

## HTTP

The HTTP options follow curl: `-k/--insecure`, `--cacert`, `--capath`, `-x/--proxy`,
`--noproxy`, `--connect-timeout` (default 10 s), `-m/--max-time` (default 60 s),
`--retry`, `-A/--user-agent`, and the usual environment variables (`HTTPS_PROXY`,
`HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
`SSL_CERT_DIR`). As in curl, `http://` and `https://` URLs have their own proxy
variable with `ALL_PROXY` as fallback, and the operating system's proxy settings are not
read. The client is ureq, blocking and without an async runtime: a command makes a few
sequential requests. TLS is rustls with the ring provider passed explicitly, as in
kartos, trusting the operating system's store unless `--cacert`/`--capath` (or the
variables) name another, which then replaces it as in curl. `-k` affects only
the transport, prints a warning and sets `insecure_transport` in JSON: trust material is
verified cryptographically either way.

## License

Copyright 2026 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](https://github.com/gematik/zero-lab/blob/main/rust/LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
