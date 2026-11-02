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

// Package oauth is the vocabulary OAuth code shares: what the standards name, with nothing that does I/O.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type of RFC 7523 section 2.2, a public name.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // an RFC URN, not a credential

// CodeChallengeMethodS256 is the PKCE code_challenge_method of RFC 7636 section 4.3.
const CodeChallengeMethodS256 = "S256"

// S256Challenge is the code_challenge of verifier under the S256 method (RFC 7636 section 4.2).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateVerifier returns a new PKCE code verifier: 32 random octets, base64url-encoded, as RFC 7636
// section 4.1 recommends.
func GenerateVerifier() string {
	octets := make([]byte, 32)
	// crypto/rand.Read never returns an error: it crashes the program rather than hand out predictable bytes.
	_, _ = rand.Read(octets)
	return base64.RawURLEncoding.EncodeToString(octets)
}
