# RFC 7520 JWE examples

The serializations of [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520) §5.6 and
§5.8-5.12 (`jwe.json`, keyed by section and figure title), copied from the RFC text with
the line breaks of the figures removed and the JSON reserialized without whitespace.
Every value is byte-for-byte the RFC's.

| Section | Key | Used for |
| --- | --- | --- |
| 5.6 | `dir`, A128GCM key | compact and general JSON decryption |
| 5.8 | A128KW key | compact, general and flattened JSON decryption |
| 5.9 | 5.8's key | `zip` is refused |
| 5.10 | 5.8's key | `aad` in the JSON serializations |
| 5.11 | 5.8's key | `alg` and `kid` in the unprotected header |
| 5.12 | 5.8's key | `enc` outside a protected header is refused |
