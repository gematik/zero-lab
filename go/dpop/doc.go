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

// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession (DPoP), RFC 9449, for
// clients and for the servers that check their proofs.
//
// A client holds a [Key] and signs one proof per request with [Key.Proof] or [Key.Sign]
// (Section 4.1, 4.2): the proof binds the HTTP method and target URI to the key, carries the
// hash of the access token it accompanies (Section 7.1) and the server's latest nonce
// (Sections 8, 9).
//
// A server checks proofs with a [Verifier]. [Verifier.Verify] performs every check of
// Section 4.3 and, given the access token and the key it is bound to, the binding checks of
// Sections 6 and 7.1. The server passes the URI it expects from its own configuration, never
// one derived from request headers a client controls (Host, X-Forwarded-Proto). Errors are
// [*Error] values that [WriteTokenError] (authorization server, Sections 5, 8) and
// [Verifier.WriteChallenge] (resource server, Sections 7.1, 9) turn into the responses the RFC
// prescribes.
//
// Time comes from a [Clock], never from the system directly, so every decision can be
// reproduced. Replay detection (Section 11.1) is a [ReplayCache]; [MemoryReplayCache] keeps it
// within one process. Server-provided nonces (Sections 8, 9) are a [NonceSource].
//
// A browser client reads the DPoP-Nonce and WWW-Authenticate response headers only if the
// server lists them in Access-Control-Expose-Headers (Sections 7.1, 8); that is the
// server's CORS configuration, not this package's.
package dpop
