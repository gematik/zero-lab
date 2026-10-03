# W3C interoperability vectors

From the XML Signature WG interoperability tests: `merlin-exc-c14n-one`
(<http://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2002JanMar/att-0032/01-merlin-exc-c14n-one.tgz>,
Merlin Hughes, Baltimore, 2002-01-14), unchanged:

| File here | Original | Selection |
|---|---|---|
| `merlin-exc-c14n-one.xml` | `exc-signature.xml` | input |
| `merlin-exc-c14n-one.id-to-be-signed.c14n` | `c14n-0.txt` | element with `Id="to-be-signed"`, Exclusive C14N without comments |
| `merlin-exc-c14n-one.SignedInfo.c14n` | `c14n-4.txt` | `dsig:SignedInfo` |

`c14n-1.txt` and `c14n-3.txt` (with an `InclusiveNamespaces` PrefixList) and `c14n-2.txt`
(with comments) are outside the TSL profile and not used. The signature itself (DSA-SHA1)
is outside the profile too; only the canonical forms are compared.

Copyright © 2002 World Wide Web Consortium. Used under the W3C Software and Document
License, <https://www.w3.org/copyright/software-license-2023/>.
