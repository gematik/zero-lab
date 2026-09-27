# Changelog

## [Unreleased]

- `tir`, the Rust `ti` command-line tool: `pki inspect` (PEM, DER or stdin; type,
  profile, admission, policies, key admissibility), `pki profiles list|describe`.
  Output: `--format auto|text|markdown|json` (`TI_FORMAT`); auto is colored text on a
  terminal and Markdown when piped; times in the system time zone. Global options:
  `--color`, `-v`, `--cache-dir`
  (`TI_CACHE_DIR`), and curl-like HTTP options (`-k`, `--cacert`, `--capath`, `-x`,
  `--noproxy`, `--connect-timeout`, `-m`, `--retry`, `-A`), validated and shown with `-v`;
  they take effect once commands download trust material.
- `pki verify`, offline: chain to the embedded roots, path, key and profile checks;
  `--env auto|prod|ref|test|dev` (`TI_ENV`), `--issuer`, `--intermediates`, `--profile`,
  `--at`. Revocation is not checked yet and reported as such. Exit 0 valid, 1 not valid,
  2 when the environment cannot be told.
- `pki verify` online: roots.json and the TSL downloaded, cached under the cache
  directory and verified against the anchor; OCSP for the end entity and its CAs, with
  the outcome per certificate. `--offline` uses the cache or the embedded roots. The
  HTTP options take effect over ureq (TLS on rustls/ring with the OS store, `--cacert`,
  `--capath`, `-k`, proxies, timeouts, `--retry`, user agent); `-v` logs each request.
- Text output no longer cuts lines to the terminal width.
- `pki roots list` and `pki tsl show` (`--ca`, `--provider`, `--root`, `--rejected`):
  the trust material behind `verify`, per environment; the TSL's CAs as a tree under
  the roots that signed them, described from their certificates only.
- `cache clear`: deletes the downloaded trust material (only the `ti-pki/` subtree).
- `schema [COMMAND]`: JSON Schema of every command's output and of errors, embedded
  and tested against real output; `agent`: the embedded AGENTS.md usage guide for the
  whole tool; `version`.
- Output: sectioned terminal views, compact Markdown (a summary, then one list; no
  tables), trees for hierarchies, PEM for certificates in JSON and Markdown, dates alone in lists and
  `2023-02-09 00:00 CET` elsewhere.
- `pki inspect` and `pki verify` read PKCS#12 (`.p12`/`.pfx`, DER or BER, legacy
  encryption included) through ti-pkcs12, with `--p12-password` (default `00`). The
  certificate with its key comes first and is `verify`'s end entity; `inspect` reports
  `private_key`. A wrong password is error kind `p12_password`, exit 4.
- `completions bash|zsh|fish|elvish|powershell`.
- `just cli-targets`: release binaries for Linux (musl), Windows and macOS.
- Release builds are stripped, fully LTO-optimised and abort on panic (6.2 → 3.5 MB).
- The executable's name comes from `ti_cli::BIN` (`tir` until parity with the Go `ti`).
