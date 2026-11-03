# Published TSL sets with their detached signatures

The three files of gemSpec_TSL 6.3.1.3 per environment, as gematik publishes them at the
automated download points of A_21182, captured together on **2026-11-01T16:47:42Z**
(the validation time of the manifest's valid entries), unchanged:

| File | Source | SHA-256 |
|---|---|---|
| `prod/ECC-RSA_TSL.xml` | `http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.xml` | `c770a18a994f699d2d9478906485d22bd5561fe1eacff637c00a321534b422ba` |
| `prod/ECC-RSA_TSL.sig` | `…/TSL-ECC/ECC-RSA_TSL.sig` | `08f96a2ff83fcbad498ef4feb09fe224e4aeac991467884f5f6310af0354b642` |
| `prod/ECC-RSA_TSL.ocsp` | `…/TSL-ECC/ECC-RSA_TSL.ocsp` | `3f922e0c0206b38a80922d8e2b262969fb2613974faf8550ce62ed1bc8cf150a` |
| `ref/ECC-RSA_TSL-ref.xml` | `http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.xml` | `f8a9f7e4ab96fbe9372d2410b5eaf8e07ac222a60ef1d017447b5b3da0b88189` |
| `ref/ECC-RSA_TSL-ref.sig` | `…/TSL-ECC-ref/ECC-RSA_TSL-ref.sig` | `b9d11c5e7990834a91db112d4ff4446c9056df6dba1fc63a2693034fcbf284df` |
| `ref/ECC-RSA_TSL-ref.ocsp` | `…/TSL-ECC-ref/ECC-RSA_TSL-ref.ocsp` | `c96e3d9587db1ee01ca23c3a43323a36108f775728db88ec376d3e744f69c179` |
| `test/ECC-RSA_TSL-test.xml` | `http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test.xml` | `a2364cfd3a3bc22867a9f949487e38146de683a5fa38e10a04e7198d2e246db3` |
| `test/ECC-RSA_TSL-test.sig` | `…/TSL-ECC-test/ECC-RSA_TSL-test.sig` | `8c672a7fae2ce895dd03a49e129c3cd7377dd77ef5d37e8f92b7ada715323dbc` |
| `test/ECC-RSA_TSL-test.ocsp` | `…/TSL-ECC-test/ECC-RSA_TSL-test.ocsp` | `f1b1191928fc69948ff57da4815e64a44d0b5a21e1521c4f25e3f9204305e0fe` |

| Set | `TSLSequenceNumber` | `Id` | `NextUpdate` | Signer | Issuer |
|---|---|---|---|---|---|
| PU | 10337 | `ID31033720261028000007Z` | 2026-11-27T00:00:07Z | TSL Signing Unit 6, serial 6 | GEM.TSL-CA3 |
| RU | 10717 | `ID31071720261028000013Z` | 2026-11-27T00:00:13Z | TSL Signing Unit 12 TEST-ONLY, serial 6 | GEM.TSL-CA28 TEST-ONLY |
| TU | 10716 | `ID31071620261028000010Z` | 2026-11-27T00:00:10Z | TSL Signing Unit 12 TEST-ONLY, serial 6 | GEM.TSL-CA28 TEST-ONLY |

The PU list on this host had the same hash as the one on the HTTPS download point
`https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml` (its `.sha2`) at capture time.
The `.ocsp` responses are signed by the delegated responders `TSL-CA3 OCSP-Signer2`
(PU) and `TSL-CA OCSP-Signer10 TEST-ONLY` (RU, TU), status `good`, with the responder
certificate included.

`derived/` holds the negative fixtures `tool/derive.py` makes from the RU set and the
PU signature, plus `stale.ocsp`, a response for the same TEST-ONLY signer produced on
2026-10-03 (from `rust/ti-pki/tests/fixtures`), older than the maximum at the capture
time.

Public data of gematik GmbH (PU); TEST-ONLY material (RU, TU).
