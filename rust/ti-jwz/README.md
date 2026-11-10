# ti-jwz

The gematik TI profiles for [jwz](../jwz/README.md), from gemSpec_Krypt V2.51.0 and
gemSpec_IDP_Dienst V2.2.0:

- `ti_jwz::ti()` for new components: ES256 with keys on P-256 and, for ePA, on
  brainpoolP256r1; ECDH-ES on P-256 and `dir`, both with A256GCM; `x5c` allowed; a JWT
  needs `exp`.
- `ti_jwz::ti_legacy()` (feature `legacy`): `ti()` plus `BP256R1` signatures, for the IDP
  and other existing interfaces. Brainpool JWE is encryption only (to the IDP's `BP-256`
  key, adding `BRAINPOOL_KEY_AGREEMENT` for that request); decrypting it is not
  supported yet.
- The profiles are jwz profiles built from constants: jwz's (`ECDSA_NIST`,
  `ECDH_ES_DIRECT_P256`, `DIRECT`, `AES_256_GCM`) and this crate's brainpool bundles,
  `EPA_BRAINPOOL_KEYS` (the `BP-256` signing curve) and, with `legacy`,
  `BRAINPOOL_SIGNATURES` (`BP256R1` on `BP-256`) and `BRAINPOOL_KEY_AGREEMENT`. jwz
  signs and encrypts under them too, so a TI client produces only what the profile
  allows.
- `ti_jwz::registry()`: the registry to parse with (brainpool names with `legacy`).
- `ti_jwz::brainpool` (feature `legacy`): the JWS algorithm `BP256R1` and the JWK curve
  `BP-256`. `brainpool::registry()` (or `register`) adds the names;
  `brainpool::backend(base)` adds BP-256 ECDSA and ECDH to any jwz backend. JWS, keys and
  policies are jwz's own code, the same as for P-256. Neither identifier is
  IANA-registered; both are gematik's (gemSpec_IDP_Dienst V2.2.0, A_20591-01, A_20695-01,
  A_20327-02) and match `go/brainpool/josebp`. Checked against the Wycheproof
  brainpoolP256r1 ECDSA and ECDH vectors, and against Go josebp and Python jwcrypto
  (`just jwz-interop`).

**Brainpool is legacy only: new components use P-256 and leave `legacy` off.**
`just brainpool-absent <crate>` fails if a crate's dependency tree contains brainpool; run
it for every new component.

ePA's `ES256` signatures on brainpool keys pass `ti()` because `ti()` lists `BP-256`
among its signing curves, the TI's stated exception to RFC 7518 §3.4; jwz's `strict()`
refuses them. The key is `brainpool::BrainpoolEs256Key`, chosen by the verifier, so a
token cannot move ES256 onto brainpool by itself. No RSA, no HMAC, no CBC-HMAC. Every rule cites its source in the crate
documentation.

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
