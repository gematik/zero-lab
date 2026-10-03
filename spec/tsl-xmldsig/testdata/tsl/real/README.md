# Published TSLs

TSL(ECC-RSA) files as gematik publishes them at the Internet download points of
gemSpec_PKI 8.2.6, named `<environment>-<TSLSequenceNumber>.xml`, unchanged:

| File | Source | SHA-256 |
|---|---|---|
| `pu-10333.xml` | `https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml` | `a95cac52ff4e64cfaf65ef0421814067d50fb0a1afd60b0265b636e370cf16f0` |
| `pu-10334.xml` | same, later | `c9f065fb221a4598e1e43e675972bc92bb1b645f70717bea0352d58881cc0cb8` |
| `tu-10687.xml` | `https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml` | `70ed0a6f5595a6a39732a4bb4128bda2266469b23e3f277c3f308a50265a90a3` |
| `tu-10713.xml` | same, later; RU (`download-ref…/ECC-RSA_TSL-ref.xml`) published the identical file | `3d528bcdac5f69ac1f45a6184fc7fd520b21bc7acec356d68c48b75c81889e84` |

Public data of gematik GmbH. A newer and an older list of one environment are kept so a
replay of the older one can be tested (TSLSIG-053).
