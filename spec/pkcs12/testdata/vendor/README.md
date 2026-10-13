# Vendor files

Two connector client identities as their vendors deliver them; no tool can regenerate them. Both
are BER-encoded, encrypt the certificate safe with pbeWithSHAAnd40BitRC2-CBC and the key with
pbeWithSHAAnd3-KeyTripleDES-CBC, and carry an HMAC-SHA-1 MAC with 102400 iterations.

| File | Content |
|---|---|
| `cgm.p12` | CGM KoCoBox: client certificate `test-cs2` with a brainpoolP256r1 key, and the KoCoBox CA certificate |
| `secunet.p12` | secunet connector: client certificate `cs200` (`valid_ec`) with a P-256 key |

The passwords are in `*-password.txt`. `SHA256SUMS` pins the files. The expected digests in
`../manifest.json` were taken from OpenSSL's decoding (`openssl pkcs12 -legacy`), not from the
implementations under test.
