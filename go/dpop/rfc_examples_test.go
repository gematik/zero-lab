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
	"net/http"
	"testing"
	"time"
)

// The RFC's own examples, copied from https://www.rfc-editor.org/rfc/rfc9449.txt with the
// RFC 8792 line wrapping undone. All four proofs are signed by one P-256 key.
const (
	// rfcFigure2Proof is the proof of Figures 2 and 5: POST https://server.example.com/token
	// at iat 1562262616.
	rfcFigure2Proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
	// rfcFigure7Proof is the proof of the refresh request of Figure 7, iat 1562265296.
	rfcFigure7Proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA"
	// rfcFigure13Proof is the proof of Figure 13: GET
	// https://resource.example.org/protectedresource with the access token of Figure 6, iat
	// 1562262618.
	rfcFigure13Proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"
	// rfcAccessToken is the access token of Figures 6 and 13.
	rfcAccessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU" //nolint:gosec // G101: the RFC's public example token.
	// rfcATH is the ath of Figure 14, the hash of rfcAccessToken.
	rfcATH = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
	// rfcJKT is the jkt of Figures 8 and 9, "the JWK SHA-256 Thumbprint of the DPoP public
	// key from the prior examples" (Section 6.1).
	rfcJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
)

// Figure 2 verifies as the token request of Figure 5 at its own iat, and its key's thumbprint
// is the jkt of Section 6.1.
func TestRFC9449_Figure2_ExampleProofVerifies(t *testing.T) {
	v := newTestVerifier(t, Config{Clock: fixedClock(time.Unix(1562262616, 0))})
	proof := mustVerify(t, v, withProof(rfcFigure2Proof), Request{
		Method: http.MethodPost,
		URI:    "https://server.example.com/token",
	})
	if proof.ID != "-BwC3ESc6acc2lTc" || proof.Method != http.MethodPost || proof.URI != "https://server.example.com/token" {
		t.Fatalf("claims %+v", proof)
	}
	if !proof.IssuedAt.Equal(time.Unix(1562262616, 0)) {
		t.Fatalf("iat %v", proof.IssuedAt)
	}
	if proof.Thumbprint != rfcJKT {
		t.Fatalf("thumbprint %s, want the jkt of Section 6.1 %s", proof.Thumbprint, rfcJKT)
	}
}

// The refresh request's proof of Figure 7 verifies at its iat.
func TestRFC9449_Figure7_RefreshProofVerifies(t *testing.T) {
	v := newTestVerifier(t, Config{Clock: fixedClock(time.Unix(1562265296, 0))})
	mustVerify(t, v, withProof(rfcFigure7Proof), Request{
		Method:     http.MethodPost,
		URI:        "https://server.example.com/token",
		Thumbprint: rfcJKT,
	})
}

// Figure 13 verifies as a protected resource request with the access token of Figure 6,
// bound to the key of the examples (Section 7.1).
func TestRFC9449_Figure13_ProtectedResourceProofVerifies(t *testing.T) {
	v := newTestVerifier(t, Config{Clock: fixedClock(time.Unix(1562262618, 0))})
	proof := mustVerify(t, v, withProof(rfcFigure13Proof), Request{
		Method:      http.MethodGet,
		URI:         "https://resource.example.org/protectedresource",
		AccessToken: rfcAccessToken,
		Thumbprint:  rfcJKT,
	})
	if proof.AccessTokenHash != rfcATH {
		t.Fatalf("ath %s", proof.AccessTokenHash)
	}
}

// ath is the base64url SHA-256 of the access token's ASCII encoding (Section 4.2), as the
// example of Figure 14 shows for the access token of Figure 6.
func TestRFC9449_4_2_AthOfFigure14(t *testing.T) {
	if got := AccessTokenHash(rfcAccessToken); got != rfcATH {
		t.Fatalf("AccessTokenHash = %s, want %s", got, rfcATH)
	}
}

// The examples' proofs fail when presented with a different method, URI or time, so the
// known answers above test the checks and not only the parser.
func TestRFC9449_Figure2_ExampleProofIsBoundToItsRequest(t *testing.T) {
	v := newTestVerifier(t, Config{Clock: fixedClock(time.Unix(1562262616, 0))})
	_, err := v.Verify(withProof(rfcFigure2Proof), Request{Method: http.MethodGet, URI: "https://server.example.com/token"})
	requireRefused(t, err, CodeInvalidProof, "DPoP proof htm does not match the request method")
	_, err = v.Verify(withProof(rfcFigure2Proof), Request{Method: http.MethodPost, URI: "https://server.example.com/other"})
	requireRefused(t, err, CodeInvalidProof, "DPoP proof htu does not match the request URI")
	late := newTestVerifier(t, Config{Clock: fixedClock(time.Unix(1562262616, 0).Add(DefaultMaxAge + time.Second))})
	_, err = late.Verify(withProof(rfcFigure2Proof), Request{Method: http.MethodPost, URI: "https://server.example.com/token"})
	requireRefused(t, err, CodeInvalidProof, "DPoP proof is too old")
}
