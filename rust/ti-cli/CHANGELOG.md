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
