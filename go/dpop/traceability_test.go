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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// requirement is one normative statement of RFC 9449, quoted, and the tests proving it.
type requirement struct {
	section string
	text    string
	tests   []string
}

// requirements are the statements this package implements. TRACEABILITY.md is generated from
// them; TestTraceability keeps both in step with the tests.
var requirements = []requirement{
	{"4.1", `DPoP = token68 (Figure 3)`, []string{
		"TestRFC9110_11_2_Token68", "TestRFC9449_4_3_02_ValueThatIsNotOneJWTIsRefused",
	}},
	{"4.2", `typ: A field with the value dpop+jwt`, []string{
		"TestRFC9449_4_2_ProofHasTheRequiredHeaderAndClaims",
	}},
	{"4.2", `alg: ... It MUST NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC)).`, []string{
		"TestRFC9449_4_2_ProofsOfEveryKeyTypeVerify", "TestRFC9449_4_2_UnsupportedKeysAreRefused",
	}},
	{"4.2", `jwk: ... It MUST NOT contain a private key.`, []string{
		"TestRFC9449_4_2_ProofJWKHasNoPrivateKeyMembers",
	}},
	{"4.2", `jti: ... at least 96 bits of pseudorandom data`, []string{
		"TestRFC9449_4_2_JtiIsRandomAndUnique",
	}},
	{"4.2", `htm: The value of the HTTP method`, []string{
		"TestRFC9449_4_2_ProofHasTheRequiredHeaderAndClaims", "TestRFC9449_4_2_InvalidProofInputIsRefused",
	}},
	{"4.2", `htu: The HTTP target URI ... without query and fragment parts`, []string{
		"TestRFC9449_4_2_ProofHasTheRequiredHeaderAndClaims", "TestRFC9449_4_2_InvalidProofInputIsRefused",
	}},
	{"4.2", `iat: Creation timestamp of the JWT`, []string{
		"TestRFC9449_4_2_ProofHasTheRequiredHeaderAndClaims",
	}},
	{"4.2", `ath: ... The value MUST be the result of a base64url encoding ... the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.`, []string{
		"TestRFC9449_4_2_AthOfFigure14", "TestRFC9449_4_2_ProofCarriesAthAndNonce",
	}},
	{"4.2", `the DPoP proof MUST also contain the following claim: nonce`, []string{
		"TestRFC9449_4_2_ProofCarriesAthAndNonce",
	}},
	{"4.3 (1)", `There is not more than one DPoP HTTP request header field.`, []string{
		"TestRFC9449_4_3_01_MoreThanOneDPoPHeaderIsRefused", "TestRFC9449_7_1_SignSetsOneProofAndTheDPoPScheme",
	}},
	{"4.3 (2)", `The DPoP HTTP request header field value is a single and well-formed JWT.`, []string{
		"TestRFC9449_4_3_02_ValueThatIsNotOneJWTIsRefused", "TestRFC9449_4_3_02_OversizedProofIsRefused", "TestRFC9449_4_3_00_MissingProofIsRefused",
	}},
	{"4.3 (3)", `All required claims per Section 4.2 are contained in the JWT.`, []string{
		"TestRFC9449_4_3_03_MissingRequiredClaimIsRefused", "TestRFC9449_4_3_03_ClaimsAreTypedAndNamedExactly",
		"TestRFC9449_4_3_03_FractionalIatIsAccepted", "TestRFC9449_4_3_03_MissingJWKHeaderIsRefused",
	}},
	{"4.3 (4)", `The typ JOSE Header Parameter has the value dpop+jwt.`, []string{
		"TestRFC9449_4_3_04_TypOtherThanDPoPJWTIsRefused", "TestRFC9449_4_3_04_TypIsComparedAsAMediaType",
	}},
	{"4.3 (5)", `The alg JOSE Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported by the application, and is acceptable per local policy.`, []string{
		"TestRFC9449_4_3_05_NoneMACAndUnacceptedAlgorithmsAreRefused", "TestRFC9449_4_3_05_SymmetricAlgorithmCannotBeConfigured",
	}},
	{"4.3 (6)", `The JWT signature verifies with the public key contained in the jwk JOSE Header Parameter.`, []string{
		"TestRFC9449_4_3_06_SignatureByAnotherKeyIsRefused", "TestRFC9449_4_3_06_TamperedPayloadIsRefused", "TestRFC9449_Figure2_ExampleProofVerifies",
	}},
	{"4.3 (7)", `The jwk JOSE Header Parameter does not contain a private key.`, []string{
		"TestRFC9449_4_3_07_PrivateKeyInJWKIsRefused",
	}},
	{"4.3 (8)", `The htm claim matches the HTTP method of the current request.`, []string{
		"TestRFC9449_4_3_08_MethodMismatchIsRefused", "TestRFC9449_Figure2_ExampleProofIsBoundToItsRequest",
	}},
	{"4.3 (9)", `The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.`, []string{
		"TestRFC9449_4_3_09_HtuIgnoresQueryAndFragment", "TestRFC9449_4_3_09_HtuMismatchIsRefused",
		"TestRFC9449_4_3_09_MisconfiguredRequestURIIsAServerError", "TestRFC9449_Figure2_ExampleProofIsBoundToItsRequest",
	}},
	{"4.3", `servers SHOULD employ syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of [RFC3986]) before comparing the htu claim.`, []string{
		"TestRFC9449_4_3_09_HtuIsComparedAfterNormalization", "TestRFC3986_6_2_HtuNormalization", "TestRFC3986_6_2_HtuNormalizationIsIdempotent",
		"TestRFC3986_5_2_4_RemoveDotSegmentsWorkedExamples", "TestRFC3986_5_4_RemoveDotSegmentsOfTheReferenceExamples", "FuzzNormalizeHTU",
	}},
	{"4.3 (10)", `If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value.`, []string{
		"TestRFC9449_4_3_10_NonceMustMatchServerNonce", "TestRFC9449_4_3_10_NonceIsNotCheckedWithoutServerNonces",
	}},
	{"4.3 (11)", `The creation time of the JWT ... is within an acceptable window (see Section 11.1).`, []string{
		"TestRFC9449_4_3_11_IatOutsideTheWindowIsRefused", "TestRFC9449_Figure2_ExampleProofIsBoundToItsRequest",
	}},
	{"4.3 (12)", `ensure that the value of the ath claim equals the hash of that access token`, []string{
		"TestRFC9449_4_3_12_AthMustMatchTheAccessToken", "TestRFC9449_Figure13_ProtectedResourceProofVerifies",
	}},
	{"4.3 (12)", `confirm that the public key to which the access token is bound matches the public key from the DPoP proof.`, []string{
		"TestRFC9449_4_3_12_AccessTokenMustBeBoundToTheProofKey", "TestRFC9449_Figure13_ProtectedResourceProofVerifies",
	}},
	{"5", `If the DPoP proof is invalid, the authorization server issues an error response per Section 5.2 of [RFC6749] with invalid_dpop_proof as the value of the error parameter.`, []string{
		"TestRFC9449_5_InvalidProofTokenError", "TestRFC9449_Figure7_RefreshProofVerifies",
	}},
	{"6.1", `The value of the jkt member MUST be the base64url encoding ... of the JWK SHA-256 Thumbprint ... of the DPoP public key`, []string{
		"TestRFC9449_6_1_ThumbprintIsTheJWKSHA256Thumbprint", "TestRFC9449_Figure2_ExampleProofVerifies",
	}},
	{"7.1", `credentials = "DPoP" 1*SP token68 (Figure 12)`, []string{
		"TestRFC9449_7_1_DPoPCredentialsAreParsed", "TestRFC9449_7_1_MalformedCredentialsAreInvalidRequest", "FuzzAccessToken",
	}},
	{"7.1", `a resource server MUST check that a DPoP proof was also received ..., check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP proof matches the public key to which the access token is bound`, []string{
		"TestRFC9449_4_3_12_AccessTokenMustBeBoundToTheProofKey", "TestRFC9449_4_3_00_MissingProofIsRefused",
	}},
	{"7.1", `The resource server MUST NOT grant access to the resource unless all checks are successful.`, []string{
		"FuzzVerify", "TestRFC9449_4_3_00_ValidProofIsAccepted",
	}},
	{"7.1", `An algs parameter SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT.`, []string{
		"TestRFC9449_7_1_Figure15_ChallengeWithoutError", "TestRFC9449_7_1_Figure16_ChallengeForInvalidKeyBinding",
	}},
	{"7.1", `invalid_dpop_proof is used to indicate that the DPoP proof itself was deemed invalid based on the criteria of Section 4.3.`, []string{
		"TestRFC9449_7_1_Figure16_ChallengeForInvalidKeyBinding", "TestRFC9449_7_1_MalformedRequestIs400",
		"TestRFC9449_7_1_MissingCredentialsHaveNoErrorCode", "TestRFC9110_5_6_4_ChallengeValuesAreQuotedStrings",
	}},
	{"8", `the authorization server responds to requests that do not include a nonce with an HTTP 400 (Bad Request) error response per Section 5.2 of [RFC6749] using use_dpop_nonce as the error code value.`, []string{
		"TestRFC9449_8_AuthorizationServerNonceError", "TestRFC9449_4_3_10_NonceMustMatchServerNonce",
	}},
	{"8", `there MUST NOT be more than one DPoP-Nonce header.`, []string{
		"TestRFC9449_8_AuthorizationServerNonceError",
	}},
	{"8", `If the nonce claim in the DPoP proof does not exactly match a nonce recently supplied by the authorization server to the client, the authorization server MUST reject the request.`, []string{
		"TestRFC9449_4_3_10_NonceMustMatchServerNonce",
	}},
	{"8.1", `nonce = 1*NQCHAR`, []string{
		"TestRFC9449_8_1_NonceSyntax", "TestRFC9449_4_2_InvalidProofInputIsRefused",
	}},
	{"8.2", `Responses that include the DPoP-Nonce HTTP header should be uncacheable`, []string{
		"TestRFC9449_8_AuthorizationServerNonceError", "TestRFC9449_9_ResourceServerNonceChallenge",
	}},
	{"9", `Resource servers use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value to accomplish this.`, []string{
		"TestRFC9449_9_ResourceServerNonceChallenge",
	}},
	{"10", `the authorization server computes the JWK Thumbprint of the proof-of-possession public key in the DPoP proof and verifies that it matches the dpop_jkt parameter value in the authorization request. If they do not match, it MUST reject the request.`, []string{
		"TestRFC9449_10_GrantBoundToAnotherKeyIsRefused",
	}},
	{"11.1", `servers MUST only accept DPoP proofs for a limited time after their creation`, []string{
		"TestRFC9449_4_3_11_IatOutsideTheWindowIsRefused",
	}},
	{"11.1", `In the context of the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof.`, []string{
		"TestRFC9449_11_1_ReplayedProofIsRefused", "TestRFC9449_11_1_RefusedProofIsNotRemembered", "TestRFC9449_11_1_FullReplayCacheFailsClosed",
	}},
	{"11.1", `a server that is tracking jti values should reject DPoP proof JWTs with unnecessarily large jti values or store only a hash thereof.`, []string{
		"TestRFC9449_11_1_ReplayCacheStoresAHashInTheContextOfTheURI",
	}},
}

// elsewhere are the normative statements that are not this package's to keep, and where they
// are kept.
var elsewhere = [][2]string{
	{"5: A token_type of DPoP MUST be included in the access token response", "the authorization server (pdp), using TokenType"},
	{"5.1: dpop_signing_alg_values_supported metadata", "the authorization server's metadata (pdp)"},
	{"6.1, 6.2: cnf.jkt in JWT access tokens and introspection responses", "the authorization server (pdp), using Proof.Thumbprint"},
	{"7.1, 8: Access-Control-Expose-Headers for WWW-Authenticate and DPoP-Nonce", "each server's CORS configuration"},
	{"7.2: a DPoP-bound access token MUST NOT be accepted with the Bearer scheme", "the resource server (pep) after validating the token's cnf"},
	{"8: Nonce values MUST be unpredictable; servers keep a window of recent nonces", "the NonceSource implementation"},
	{"10: dpop_jkt in the authorization request", "the authorization server (pdp) and the client, using Key.Thumbprint"},
}

const traceabilityFile = "TRACEABILITY.md"

// TestTraceability checks that every requirement names tests that exist and that every
// test of the RFCs is listed, and that TRACEABILITY.md is the table generated from them.
// DPOP_BLESS=1 rewrites it.
func TestTraceability(t *testing.T) {
	tests := testFunctions(t)
	listed := map[string]bool{}
	for _, r := range requirements {
		if len(r.tests) == 0 {
			t.Errorf("%s %q has no test", r.section, r.text)
		}
		for _, name := range r.tests {
			if !slices.Contains(tests, name) {
				t.Errorf("%s names %s, which does not exist", r.section, name)
			}
			listed[name] = true
		}
	}
	for _, name := range tests {
		if (strings.HasPrefix(name, "TestRFC") || strings.HasPrefix(name, "Fuzz")) && !listed[name] {
			t.Errorf("%s proves no listed requirement", name)
		}
	}
	want := renderTraceability()
	if os.Getenv("DPOP_BLESS") == "1" {
		if err := os.WriteFile(traceabilityFile, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(traceabilityFile)
	if err != nil || string(got) != want {
		t.Fatalf("%s is stale: run DPOP_BLESS=1 go test -run TestTraceability ./dpop", traceabilityFile)
	}
}

// testFunctions are the names of the Test and Fuzz functions in the package's test files.
func testFunctions(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	fset := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil &&
				(strings.HasPrefix(fn.Name.Name, "Test") || strings.HasPrefix(fn.Name.Name, "Fuzz")) {
				names = append(names, fn.Name.Name)
			}
		}
	}
	slices.Sort(names)
	return names
}

func renderTraceability() string {
	var b strings.Builder
	b.WriteString("# RFC 9449 traceability of go/dpop\n\n")
	b.WriteString("Generated by `TestTraceability` from `traceability_test.go`; do not edit. ")
	b.WriteString("Each row quotes a normative statement of [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) ")
	b.WriteString("and names the tests that prove it.\n\n")
	b.WriteString("| Section | Statement | Tests |\n|---|---|---|\n")
	for _, r := range requirements {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.section, escapeCell(r.text), "`"+strings.Join(r.tests, "`<br>`")+"`")
	}
	b.WriteString("\n## Kept outside this package\n\n| Statement | Where |\n|---|---|\n")
	for _, e := range elsewhere {
		fmt.Fprintf(&b, "| %s | %s |\n", escapeCell(e[0]), escapeCell(e[1]))
	}
	return b.String()
}

func escapeCell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
