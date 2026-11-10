# ti-tls

TLS server verification for clients of the gematik Telematikinfrastruktur (TI), under the two
profiles of [`spec/pki-validation`](../../spec/pki-validation/README.md):

- **`ti`**, for servers of the TI: trust only from the verified TSL and roots.json, judged by
  `ti_pki::tls::ServerCheck` (TUC_PKI_018 with Tab_PKI_273, C.FD.TLS-S/C.ZD.TLS-S, the host in
  the commonName or a `dNSName`, OCSP stapled or asked).
- **`web`**, for servers on the internet: the host system's default roots (`WebCheck::system`,
  as Go and the containers' `ca-certificates` have them), with the requirements gematik and the
  ZETA SDK add: end-entity keys ECDSA P-256/P-384 or RSA ≥ 3000, CA keys RSA ≥ 2048, no SHA-1,
  MD5 or SHA-224, serverAuth, the host in a `dNSName`, at most 398 days of validity, and a
  revocation status from stapled OCSP, the responder or the CRL; a revoked one refuses.

The profile is the endpoint's, by configuration; neither falls back to the other.

Two `web` rules deviate from gemSpec_Krypt, as the spec's
[Deviations](../../spec/pki-validation/README.md#deviations) record: an end entity with RSA
2048 to 2999 bits is accepted with the warning `key_phased_out` (A_28976 asks for 3000), and a
server whose status no source gives is accepted with `revocation_unavailable` (A_27857-02
requires one), since Let's Encrypt ended OCSP and responders fail now and then. Such a verdict
is not reused. `Verdict::warnings` carries them, `WebVerifier::with_warning_observer` tells the
host of each server a handshake accepted and its warnings, and a host that needs the strict
rules judges with `WebVerifier::verify` or `WebCheck::verify` and refuses such a verdict in its
own `ServerCertVerifier`.

A Konnektor is verified by neither: `konnektor::Trust` holds the trust its `.kon` file
configures, as the Go client verifies it. An end-entity certificate in the trust store is a
pin, accepted by equality; otherwise the chain must lead to one of its CA certificates and
name `expectedHost`, else the URL's host, which `konnektor::server_name` also makes the SNI;
an empty trust store means the operating system's, through a verifier the host supplies; and
`insecureSkipVerify` accepts any certificate, still checking the handshake signatures.

- `client_config(verifier)`: a rustls `ClientConfig` offering TLS 1.3 and 1.2, AES-GCM with
  ECDHE, and P-256/P-384 only, as `testdata/handshake.json` lists it.
- `TiVerifier` and `WebVerifier`: the profiles as rustls `ServerCertVerifier`s, over one snapshot
  of trust material each; `TiVerifier::replace` swaps the TI's for a refreshed TSL while
  connections use the verifier. An accepted verdict is reused for the same chain and host until
  its certificate, its revocation status (its `nextUpdate`, at most an hour under `ti` and a day
  under `web`) or its snapshot ends; a refusal never is, nor a `web` verdict without a status.
  A verifier keeps at most 4096 verdicts, with their warnings.
- `Fetch`: the host's way to an OCSP responder or CRL host for `web`; `ti` takes ti-pki's
  `OcspChecker` over the host's transport.

Certificates and handshake signatures verify with ti-pki's algorithms (brainpool included for
`ti`); rustls-webpki builds the `web` paths. The corpus of the spec is run by
`tests/corpus.rs` here and `tests/tls_corpus.rs` in ti-pki.

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
