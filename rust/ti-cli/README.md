# ti-cli

`tir`, the command-line tool for the gematik Telematikinfrastruktur (TI), in Rust. It
builds on [`ti-pki`](../ti-pki) and is called `tir` until it covers what the Go `ti`
does; then it becomes `ti`.

```sh
just install                      # cargo install into ~/.cargo/bin/tir
tir pki inspect card.pem          # what the TI reads from a certificate
tir pki inspect - < card.der
tir pki inspect card.pem > card.md  # piped output is Markdown
tir --format json pki inspect card.pem | jq '.certificates[0].certificate_type'
tir pki profiles list
tir pki profiles describe smb-aut
tir pki verify card.pem                   # exit 0 valid, 1 not valid
tir pki verify card.pem --offline         # cached trust material, no OCSP
```

## Verify

`tir pki verify` builds the chain to the TI roots through the CAs of the TSL and
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

## Conventions

The tool is meant for people and for agents alike:

- Results go to stdout, diagnostics (`-v`, `-vv`) and errors to stderr.
- `--format auto|text|markdown|json` (or `TI_FORMAT`). `auto` gives aligned, colored text
  on a terminal and Markdown (CommonMark with GFM tables) when piped: readable in notes,
  chats and by agents. Commands describe their output once; text and Markdown are two
  renderings of the same document.
- `json` writes one document with a `"schema"` version; fields are only added within a
  schema version. Errors in JSON mode are `{"schema":1,"error":{"kind","message","hint"}}`
  on stderr.
- Times in text and Markdown are in the system time zone with offset and abbreviation,
  e.g. `2023-02-09 00:00:00 +01:00 (CET)` (`TZ` is honoured); JSON keeps RFC 3339 in UTC.
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
