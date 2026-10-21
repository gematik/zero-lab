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

package dpop

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Error codes of RFC 9449 and of the RFCs it builds on.
const (
	// CodeInvalidProof: the DPoP proof failed a check of Section 4.3 (Sections 5, 7.1).
	CodeInvalidProof = "invalid_dpop_proof"
	// CodeUseNonce: the proof lacks the server's current nonce (Sections 8, 9).
	CodeUseNonce = "use_dpop_nonce"
	// CodeInvalidToken: the access token is not bound to the proof's key (Section 7.1,
	// Figure 16; RFC 6750 Section 3.1).
	CodeInvalidToken = "invalid_token"
	// CodeInvalidRequest: the Authorization header is malformed (RFC 6750 Section 3.1).
	CodeInvalidRequest = "invalid_request"
)

// Error is why a request was refused, in the vocabulary the RFC's responses use.
type Error struct {
	// Code is one of the Code constants; empty when the request carried no credentials at
	// all, which a resource server answers with a challenge but no error (Figure 15).
	Code string
	// Description is a short, fixed explanation for developers (RFC 6749 Section 5.2). It
	// never echoes request content.
	Description string
	// Nonce is a fresh nonce to send in the DPoP-Nonce header, when the server uses nonces
	// (Sections 8, 9).
	Nonce string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return "dpop: " + e.Description
	}
	return "dpop: " + e.Code + ": " + e.Description
}

func proofError(description string) *Error {
	return &Error{Code: CodeInvalidProof, Description: description}
}

// WriteTokenError answers a token request the authorization server refuses because of its
// DPoP proof: 400 with an RFC 6749 Section 5.2 error body (Section 5), and the server's
// nonce in DPoP-Nonce, uncacheable (Sections 8, 8.2).
func WriteTokenError(w http.ResponseWriter, e *Error) {
	if e.Nonce != "" {
		SetNonce(w, e.Nonce)
	}
	body, err := json.Marshal(struct {
		Error       string `json:"error"`
		Description string `json:"error_description,omitempty"`
	}{e.Code, e.Description})
	if err != nil {
		// Two strings cannot fail to marshal.
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(body)
}

// WriteChallenge answers a resource request refused because of its DPoP proof or access
// token: a WWW-Authenticate challenge of the DPoP scheme with the error, its description and
// the accepted algorithms (Section 7.1), and the server's nonce in DPoP-Nonce (Section 9).
// The status is 400 for a malformed request and 401 otherwise (RFC 6750 Section 3.1).
func (v *Verifier) WriteChallenge(w http.ResponseWriter, e *Error) {
	if e.Nonce != "" {
		SetNonce(w, e.Nonce)
	}
	w.Header().Set("WWW-Authenticate", v.Challenge(e))
	status := http.StatusUnauthorized
	if e.Code == CodeInvalidRequest {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
}

// Challenge is the WWW-Authenticate value for e: the DPoP scheme with error and
// error_description when there is an error, and always algs (Section 7.1, Figures 15 and 16).
// For servers that write their own error responses; [Verifier.WriteChallenge] uses it.
func (v *Verifier) Challenge(e *Error) string {
	var params []string
	if e.Code != "" {
		params = append(params, `error=`+quote(e.Code))
		if e.Description != "" {
			params = append(params, `error_description=`+quote(e.Description))
		}
	}
	algs := make([]string, len(v.algorithms))
	for i, alg := range v.algorithms {
		algs[i] = string(alg)
	}
	params = append(params, `algs=`+quote(strings.Join(algs, " ")))
	return "DPoP " + strings.Join(params, ", ")
}

// SetNonce sends nonce in the DPoP-Nonce header and makes the response uncacheable, so no
// cache hands a stale nonce to the next request (Section 8.2).
func SetNonce(w http.ResponseWriter, nonce string) {
	w.Header().Set("DPoP-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
}

// quote is s as an RFC 9110 Section 5.6.4 quoted-string. The descriptions are the package's
// own constants, so the escaping is a guard, not a filter of client input.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || r > 0x7e:
			// Not allowed in a quoted-string as this package writes it: dropped.
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
