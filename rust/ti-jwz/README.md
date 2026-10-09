# ti-jwz

The gematik TI profiles for [jwz](../jwz/README.md), from gemSpec_Krypt V2.50.0 and
gemSpec_IDP_Dienst V2.2.0:

- `ti_jwz::ti()` for new components: ES256; ECDH-ES on P-256 and `dir`, both with
  A256GCM; `x5c` allowed; a JWT needs `exp`.
- `ti_jwz::ti_legacy()` (feature `legacy`): `ti()` plus `BP256R1` signatures and ECDH-ES
  with an `epk` on `BP-256`, for the IDP and other existing interfaces.
- `ti_jwz::registry()`: the registry to parse with (brainpool names with `legacy`).

ePA's `ES256` signatures on brainpool keys pass `ti()`: the curve is the key's, chosen
with `jwz_brainpool::BrainpoolEs256Key`. No RSA, no HMAC, no CBC-HMAC. Every rule cites
its source in the crate documentation.

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
