// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Package titls verifies TLS servers under the two profiles of spec/pki-validation, ti and web, for
// crypto/tls clients. It follows Rust's ti-tls rule for rule, and the shared corpus holds the two together.
//
// The host owns the transport and this package owns trust: the host dials, chooses the profile of each
// endpoint (TLSV-001) and supplies an *http.Client for revocation through a [Fetcher]; the package builds
// the tls.Config whose VerifyConnection decides, and opens no connection itself.
//
//   - ti: [TiVerifier] runs tipki's [tipki.ServerCheck] over the current snapshot of a [TrustSource]. Its
//     configuration verifies everything in VerifyConnection, since crypto/x509 cannot verify the TI's
//     brainpool CAs.
//   - web: [WebVerifier] runs [WebCheck] over the system's roots ([SystemWebCheck]); crypto/tls verifies
//     the path as well, and VerifyConnection adds the profile's keys, name, validity period and
//     revocation (stapled OCSP, the OCSP responder, the CRL).
//
// A ti host:
//
//	source := titls.NewTrustSource(store) // source.Swap(newStore) after each TSL reload
//	responder := tipki.NewOCSPChecker(titls.OCSPTransport(titls.NewHTTPFetcher(client)))
//	config := titls.NewTiVerifier(source, responder, titls.Options{}).ClientConfig()
//
// A web host:
//
//	check, err := titls.SystemWebCheck()
//	config := titls.NewWebVerifier(check, titls.NewHTTPFetcher(client), titls.Options{}).ClientConfig()
//
// Accepted verdicts are reused for the same chain, host and profile, under ti also the same trust snapshot,
// until the earliest of notAfter, the status's nextUpdate and the profile's window (TLSV-050, TLSV-051): at
// most [DefaultCacheSize] of them unless configured; refusals never.
//
// Where crypto/tls cannot do what spec/pki-validation/testdata/handshake.json lists:
//
//   - TLS 1.3 cipher suites are not configurable: TLS_CHACHA20_POLY1305_SHA256 is offered as well. A
//     connection that negotiates it is refused in VerifyConnection, so it is offered but never accepted
//     (TLSV-011).
//   - The client's signature_algorithms are not configurable. crypto/tls also offers Ed25519, ML-DSA and
//     ecdsa_secp521r1_sha512, and the SHA-1 schemes when the process runs with GODEBUG=tlssha1=1. The
//     server signs with its certificate's key, which both profiles admit only on P-256, P-384 or RSA, so
//     Ed25519, ML-DSA and P-521 signatures cannot be accepted; in TLS 1.2 a P-256 key may sign with
//     SHA-384 or SHA-512, a pairing TLSV-013 does not list but whose hashes it allows (TLSV-013).
//   - crypto/tls has no brainpool groups or brainpool signature schemes (TLSV-012, TLSV-013), and it parses
//     every presented certificate with crypto/x509 before VerifyConnection runs: a ti server presenting a
//     brainpool certificate fails the handshake there. ePA's servers present a P-256 end entity; the
//     brainpool CA above it comes from the TSL, which crypto/tls never parses.
//   - An IP-address host is refused: crypto/tls sends no SNI for it and reports no server name to
//     VerifyConnection, so there is no reference identity to check (TLSV-024).
//
// The configurations set no ClientSessionCache, so the client never resumes (TLSV-014). A host that adds
// one still has every resumed handshake checked, as crypto/tls calls VerifyConnection on resumption too.
// Go cannot make a tls.Config immutable: no option of this package turns a rule off, but a host that
// clears VerifyConnection or RootCAs on the returned configuration does.
package titls
