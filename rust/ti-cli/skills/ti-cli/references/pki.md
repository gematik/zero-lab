# ti pki: certificates and trust

## Contents
- Inspect and verify
- Reading a verify report
- Profiles, roots and the TSL
- Bundles and truststores
- PKCS#12 and raw signatures
- Error kinds

## Inspect and verify

Input is PEM, DER or PKCS#12 (`.p12`, `.pfx`); `-` reads stdin. A PEM file may hold the
chain with the end entity first. In a PKCS#12 file the certificate with its private key
is the end entity.

```sh
ti --format json pki inspect card.pem             # what the TI reads from a certificate
ti --format json pki inspect - < card.der
ti pki inspect roots.pem --short                  # a row per certificate
ti --format json pki verify card.pem              # chain, profile, OCSP; exit 0/1
ti --format json pki verify card.pem --env ref    # skip environment detection
ti --format json pki verify card.pem --offline    # no network, no OCSP
ti --format json pki verify tls.pem --fqdn epa-as-1.ref.epa4all.de
ti --format json pki verify --connect epa-as-1.ref.epa4all.de     # the server's chain
ti --format json pki verify card.pem --at 2025-06-01T00:00:00Z    # judge status at T
ti --format json pki verify card.pem --nist-only  # chain must reach a non-brainpool root
```

## Reading a verify report

Top-level fields of `pki verify` JSON: `valid`, `environment`, `at`,
`certificate_type`, `profile`, `trust`, `revocation_checked`, `revocation_mode`,
`insecure_transport`, `ocsp`, `chain`, `errors`, `warnings`.

- `valid` is the verdict; `errors` says why it is false.
- `warnings` never change the verdict but deserve a look.
- `revocation_checked: false` means revocation was not checked.
- `chain[].revocation` is the OCSP answer per certificate (the root has none).
  `cached: true` means an earlier run's answer, and `produced_at` says how old. An
  unreachable responder under hard-fail gives an `ocsp_unavailable` error naming its URL.
- `environment.detection` says how `--env auto` chose.
- `trust.note` is set when trust material is partial; then pass `--issuer`.
- With `--at T`: a certificate revoked after T is valid with warning
  `revoked_after_reference_time`; `chain[].revocation` keeps `status: revoked`.
- A CA the TSL lists as revoked still vouches for what it issued before its
  `StatusStartingTime`: valid with `issued_before_ca_revocation`, later ones fail with
  `ca_revoked_in_tsl`.

Typical filters:

```sh
ti --format json pki verify card.pem | jq '{valid, type: .certificate_type, errors, warnings}'
ti --format json pki verify card.pem | jq -r '.chain[] | [.subject, .revocation.status // "-"] | @tsv'
ti --format json pki verify card.pem | jq -r '.chain[0].pem' > end-entity.pem   # PEM is in `pem` fields
```

## Profiles, roots and the TSL

```sh
ti --format json pki profiles list
ti --format json pki profiles describe hci-aut
ti --format json pki profiles describe hci-aut --env ref   # tsl.cas: CAs the TSL allows
ti --format json pki roots list --env ref                  # roots reached from the anchor
ti --format json pki tsl show --env ref                    # CAs under the roots that signed them
ti --format json pki tsl show --rejected                   # CAs no verified root signed
ti --format json pki tsl show --ca SMCB-CA51               # also --provider, --root
ti --format json pki tsl verify tsl.xml --previous old.xml # exit 0 valid, 1 not
ti pki tsl export --env ref -o tsl.xml                     # the TSL as published, once verified
```

`pki roots list` and `pki tsl show` cannot detect an environment: `TI_ENV=auto` means
`prod` there and `--env auto` is exit 2.

`tsl verify` checks signature, signer under the embedded TSL signer CA, `NextUpdate`
(`--grace`), the signer's OCSP status (not with `--offline`/`--at`) and, with
`--previous`, the sequence number. `result` is `valid` or `invalid`; invalid has `code`
(e.g. `xml_signature_error`), `rule` (`TSLSIG-nnn`) and `detail`.

## Bundles and truststores

`roots bundle`, `tsl bundle` and `tsl export` write to stdout, or to `-o FILE`
(`--force` replaces an existing file).

```sh
ti pki roots bundle --env ref > roots.pem                     # CA bundle for curl, openssl, Go
ti pki roots bundle --p12 --p12-password changeit -o roots.p12   # Java truststore
ti pki tsl bundle --env ref --ca SMCB -o smcb.pem
ti pki tsl bundle --env ref --ca KOMP-CA54 --ca KOMP-CA55 -o komp.pem      # repeated: any of
ti pki tsl bundle --env ref --connect epa-as-1.ref.epa4all.de --with-roots -o epa.pem
ti pki tsl bundle --env ref --cert chain.pem --p12 --p12-password changeit -o ts.p12
ti pki tsl bundle --env prod --issues TLS-S --with-roots -o tls.pem        # every TLS server CA
ti pki tsl bundle --env prod --issues TLS-S --with-roots --nist-only -o tls-nist.pem
```

- Filters `--ca`, `--provider`, `--root`, `--issues` are repeatable: repeated values of
  one filter match any; different filters must all match.
- `--issues TYPE` matches certificate types whose name contains TYPE (case and `.`/`-`
  insensitive): `TLS-S`, `HCI.AUT`, `fd-tls-s`.
- `--connect HOST[:PORT]` / `--cert FILE` narrow to the CAs that issued those
  certificates: the bundle a client of that server needs. TI servers such as the ePA
  Aktensysteme send only their own certificate, so clients need the issuing CA from the
  TSL.
- `--with-roots` adds the roots, for clients that accept only a self-signed anchor.
- `--p12` needs `--p12-password`.
- `--nist-only` drops brainpool roots/CAs for tools without brainpool support.
- Revoked CAs are left out of bundles (curl/Java cannot apply the date rule).
- With `--format json` these report instead of printing: each certificate's `pem` when
  nothing was written, `output` when a file was.

## PKCS#12 and raw signatures

```sh
ti pki pkcs12 convert old.p12 new.p12 --p12-password-path pw.txt   # DER, PBES2 AES-256, SHA-256 MAC, mode 0600; --force to replace
ti pki verify-signature --cert vau.pem --data keys.cbor --signature sig.bin
```

- `convert` produces files OpenSSL 3 and Go read without `-legacy`.
- `verify-signature` checks one ECDSA-SHA256 signature (DER, or raw r‖s of 64 bytes) and
  reports `valid`, `signature_format` and the signer certificate. It says nothing about
  the certificate itself: use `pki verify` for that.
- A wrong PKCS#12 password is exit 4, error kind `p12_password`.

## Error kinds

`environment_invalid` (exit 2), `p12_password` (4), `output_exists` (5),
`trust_material_unavailable` (3), `ocsp_unavailable` (an error inside the report).
`--format json` errors always carry a `hint`.
