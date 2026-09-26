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
