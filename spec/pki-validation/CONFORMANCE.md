# Conformance

An implementation conforms when it judges every case of [`testdata/manifest.json`](testdata/manifest.json)
as the case expects, offers what [`testdata/handshake.json`](testdata/handshake.json) lists, and proves the
rules no file can hold with tests named after them.

## The cases

`manifest.json` has two parts.

- `trust`: the trust material a case names. `ti` is a root (`roots`) and the CAs a verified TSL would supply
  (`tsl_cas`, each with the certificate types the list lets it issue); `ti-no-tsl` has no TSL, which an
  implementation reports as `trust_material_unavailable`. `web` is a root standing in for the host system's
  store (TLSV-040).
- `cases`: each with
  - `trust`, which names the material and so the profile;
  - `chain`, the certificates as the server sends them, end entity first;
  - `host`, the name the client connected to, as given (case and trailing dot included);
  - `at`, the reference time;
  - `stapled_ocsp`, the response the server staples, or `null`;
  - `responder_ocsp` and `crl`, what the network answers when the implementation asks the end entity's
    OCSP responder or fetches its CRL, or `null` when that source does not answer;
  - `expect`, the result code of the README, and `warnings`, the warnings it reports;
  - `rules`, the rules the case proves.

An adapter feeds each case through the implementation's verification entry point, with a transport that
answers OCSP and CRL requests from the case and fails every other request, and a clock fixed at `at`. The
OCSP grace period is the default, 10 minutes. The adapter compares the code and the warnings exactly.

OCSP responses carry SHA-256 CertIDs, as the TI's responders answer; an implementation matches a CertID by
the hash algorithm it names.

## The handshake

`handshake.json` lists, per profile, the TLS versions, cipher suites, groups and signature schemes a client
offers (TLSV-010 to 013). An implementation proves it with a test that reads the configuration it builds,
not with a connection.

## Rules proved by the implementations' own tests

- TLSV-002: a refusal ends the handshake with a fatal alert, and no option skips a rule.
- TLSV-014: renegotiation and resumption, as far as the TLS library leaves them to the caller.
- TLSV-050, TLSV-051: verdicts and revocation status reused, and not past the earliest reason to stop.

## Regenerating

From this directory: `bash testdata/generate.sh` makes the certificates, OCSP responses and CRLs (every
certificate gets a new key), and `python3 -I testdata/manifest.py` writes the manifest and checks that each
file it names exists. Both implementations' corpus tests must then pass before the files are committed.
