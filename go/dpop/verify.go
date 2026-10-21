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
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Defaults of [Config].
const (
	// DefaultMaxAge is how old a proof may be: a few minutes, as Section 11.1 suggests for
	// the window in which a proof is accepted.
	DefaultMaxAge = 5 * time.Minute
	// DefaultLeeway is how far into the future a proof's iat may lie, for clock skew.
	DefaultLeeway = 10 * time.Second
	// DefaultMaxSize bounds the DPoP header value: a proof with an EC or Ed25519 key is under
	// 1 KiB, an RSA one under 2 KiB.
	DefaultMaxSize = 8 << 10
)

// maxNumericDate is 9999-12-31T23:59:59Z, the last instant an iat is read as.
const maxNumericDate = 253402300799

// asymmetric are the registered asymmetric JWS algorithms go-jose verifies (Section 4.3,
// check 5; RFC 7518 Section 3.1, RFC 8037 Section 3.1).
var asymmetric = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.EdDSA,
}

// NonceSource is the server's nonce state (Sections 8, 9).
type NonceSource interface {
	// Valid reports whether nonce is one the server recently supplied; it must match
	// exactly (Section 8).
	Valid(nonce string) bool
	// Fresh returns an unpredictable nonce for the client's next proof (Section 8).
	Fresh() (string, error)
}

// ReplayCache remembers the proofs a server has accepted (Section 11.1).
type ReplayCache interface {
	// Seen records id until the given time and reports whether it was recorded already. An
	// error means the server cannot tell, and the proof is refused.
	Seen(id string, until time.Time) (bool, error)
}

// Config is a [Verifier]'s policy.
type Config struct {
	// Algorithms are the JWS algorithms accepted in proofs (Section 4.3, check 5). Each must
	// be a registered asymmetric one; none and MAC algorithms are refused (Section 4.2).
	// Empty means ES256.
	Algorithms []jose.SignatureAlgorithm
	// MaxAge is how old a proof's iat may be (Section 4.3, check 11; Section 11.1). Zero
	// means [DefaultMaxAge].
	MaxAge time.Duration
	// Leeway is how far into the future a proof's iat may lie. Zero means [DefaultLeeway].
	Leeway time.Duration
	// MaxSize bounds the DPoP header value in bytes. Zero means [DefaultMaxSize].
	MaxSize int
	// Clock is the time proofs are judged at. Nil means the system clock.
	Clock Clock
	// Nonces, when set, makes the server require its nonce in every proof (Sections 8, 9).
	Nonces NonceSource
	// Replay, when set, refuses a proof whose jti was accepted before (Section 11.1).
	Replay ReplayCache
}

// Verifier checks DPoP proofs (Section 4.3) under one [Config]. It is safe for concurrent use
// when its NonceSource and ReplayCache are.
type Verifier struct {
	algorithms []jose.SignatureAlgorithm
	maxAge     time.Duration
	leeway     time.Duration
	maxSize    int
	clock      Clock
	nonces     NonceSource
	replay     ReplayCache
}

// NewVerifier returns a Verifier for config, or an error if it allows an algorithm Section
// 4.2 forbids or that is not supported.
func NewVerifier(config Config) (*Verifier, error) {
	algorithms := slices.Clone(config.Algorithms)
	if len(algorithms) == 0 {
		algorithms = []jose.SignatureAlgorithm{jose.ES256}
	}
	for _, alg := range algorithms {
		if !slices.Contains(asymmetric, alg) {
			return nil, fmt.Errorf("dpop: %q is not an asymmetric signature algorithm", alg)
		}
	}
	v := &Verifier{
		algorithms: algorithms,
		maxAge:     cmp.Or(config.MaxAge, DefaultMaxAge),
		leeway:     cmp.Or(config.Leeway, DefaultLeeway),
		maxSize:    cmp.Or(config.MaxSize, DefaultMaxSize),
		clock:      clockOrSystem(config.Clock),
		nonces:     config.Nonces,
		replay:     config.Replay,
	}
	if v.maxAge < 0 || v.leeway < 0 || v.maxSize < 0 {
		return nil, errors.New("dpop: negative MaxAge, Leeway or MaxSize")
	}
	return v, nil
}

// Request is what the server knows about the request a proof came with.
type Request struct {
	// Method is the request's HTTP method (check 8).
	Method string
	// URI is the request's target URI as the server is configured to be reached, e.g. its
	// token endpoint from its metadata: never derived from Host or X-Forwarded-* headers,
	// which the client controls. Its query and fragment are ignored (check 9).
	URI string
	// AccessToken is the access token presented with the request, if any; the proof must
	// then carry its hash (check 12, Section 7.1).
	AccessToken string
	// Thumbprint is the JWK SHA-256 thumbprint (cnf.jkt, Section 6.1) of the key the access
	// token, or the authorization code (Section 10), is bound to. Required with AccessToken.
	Thumbprint string
}

// Proof is a checked DPoP proof.
type Proof struct {
	// ID is the proof's jti.
	ID string
	// Method and URI are its htm and htu.
	Method, URI string
	// IssuedAt is its iat.
	IssuedAt time.Time
	// AccessTokenHash and Nonce are its ath and nonce, empty when absent.
	AccessTokenHash, Nonce string
	// Key is the public key from its jwk header.
	Key jose.JSONWebKey
	// Thumbprint is that key's JWK SHA-256 thumbprint (Section 6.1): the jkt to bind an
	// access token to.
	Thumbprint string
}

// Verify checks the DPoP proof in header against req, performing every check of Section 4.3
// and, for an access token, the binding of Section 7.1. A refusal is an [*Error]; any other
// error means the server could not decide (its nonce or replay state failed).
func (v *Verifier) Verify(header http.Header, req Request) (*Proof, error) {
	values := header.Values(HeaderName)
	if len(values) == 0 {
		return nil, proofError("no DPoP proof")
	}
	// Check 1: not more than one DPoP header field.
	if len(values) > 1 {
		return nil, proofError("more than one DPoP header")
	}
	raw := values[0]
	if len(raw) > v.maxSize {
		return nil, proofError("DPoP proof too large")
	}
	// Check 2: a single, well-formed JWT in the token68 syntax (Section 4.1). A compact JWS
	// has exactly one signature.
	if !isToken68(raw) {
		return nil, proofError("DPoP header is not a single token68 value")
	}
	// Check 7 before parsing, so the refusal names it: go-jose also refuses an embedded
	// private key, but without saying why.
	if headerHasPrivateKey(raw) {
		return nil, proofError("DPoP proof jwk contains a private key")
	}
	// Check 5 is enforced by go-jose while parsing: only the configured algorithms, all
	// asymmetric, are accepted; none never is.
	jws, err := jose.ParseSignedCompact(raw, v.algorithms)
	if err != nil {
		return nil, proofError("DPoP proof is not a well-formed JWS with an accepted algorithm")
	}
	protected := jws.Signatures[0].Protected
	// Check 4: typ is dpop+jwt.
	if !isProofType(protected.ExtraHeaders[jose.HeaderType]) {
		return nil, proofError("DPoP proof typ is not dpop+jwt")
	}
	// Check 3 for the header (Section 4.2): jwk is present and a valid key.
	jwk := protected.JSONWebKey
	if jwk == nil || !jwk.Valid() {
		return nil, proofError("DPoP proof has no valid jwk header")
	}
	// Check 7: jwk does not contain a private key.
	if !jwk.IsPublic() {
		return nil, proofError("DPoP proof jwk contains a private key")
	}
	// Check 6: the signature verifies with the key from jwk.
	payload, err := jws.Verify(jwk)
	if err != nil {
		return nil, proofError("DPoP proof signature does not verify with its jwk")
	}
	// Check 3 for the payload: jti, htm, htu and iat are present.
	c, err := parseClaims(payload)
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		ID:              c.ID,
		Method:          c.Method,
		URI:             c.URI,
		IssuedAt:        c.IssuedAt,
		AccessTokenHash: c.ATH,
		Nonce:           c.Nonce,
		Key:             *jwk,
	}
	if proof.Thumbprint, err = thumbprintOf(*jwk); err != nil {
		return nil, proofError("DPoP proof jwk has no thumbprint")
	}
	// Check 8: htm matches the request's method. Methods are case-sensitive (RFC 9110
	// Section 9.1).
	if proof.Method != req.Method {
		return nil, proofError("DPoP proof htm does not match the request method")
	}
	// Check 9: htu matches the request's URI, ignoring query and fragment, after RFC 3986
	// normalization.
	if err := v.checkURI(proof.URI, req.URI); err != nil {
		return nil, err
	}
	// Check 10: the server's nonce, when it uses nonces (Sections 8, 9).
	if err := v.checkNonce(proof.Nonce); err != nil {
		return nil, err
	}
	// Check 11: iat within the window (Section 11.1).
	now := v.clock.Now()
	if proof.IssuedAt.Before(now.Add(-v.maxAge)) {
		return nil, proofError("DPoP proof is too old")
	}
	if proof.IssuedAt.After(now.Add(v.leeway)) {
		return nil, proofError("DPoP proof is issued in the future")
	}
	// Check 12: with an access token, ath is its hash and the token is bound to this key
	// (Section 7.1); without one, a binding the server knows of (Section 10) still holds.
	if err := checkBinding(proof, req); err != nil {
		return nil, err
	}
	// Section 11.1: a proof is accepted once. Checked last, so only proofs that passed
	// every other check take a place in the cache.
	if v.replay != nil {
		seen, err := v.replay.Seen(replayID(proof), proof.IssuedAt.Add(v.maxAge+v.leeway))
		if err != nil {
			return nil, fmt.Errorf("dpop: replay cache: %w", err)
		}
		if seen {
			return nil, proofError("DPoP proof was used before")
		}
	}
	return proof, nil
}

// privateKeyMembers are the JWK members that hold private key material: d of EC, OKP and RSA
// keys, the RSA CRT parameters, and k of symmetric keys (RFC 7518 Sections 6.2.2, 6.3.2,
// 6.4.1; RFC 8037 Section 2).
var privateKeyMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// headerHasPrivateKey reports whether the jwk in the protected header of the compact JWS raw
// has a private key member (Section 4.3, check 7). A header that does not decode is left to
// the parser, which refuses it.
func headerHasPrivateKey(raw string) bool {
	segment, _, _ := strings.Cut(raw, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	var header struct {
		JWK map[string]json.RawMessage `json:"jwk"`
	}
	if json.Unmarshal(decoded, &header) != nil {
		return false
	}
	for _, member := range privateKeyMembers {
		if _, ok := header.JWK[member]; ok {
			return true
		}
	}
	return false
}

// replayID identifies a proof for the replay cache: the jti "in the context of the target
// URI" and of the key, and only "a hash thereof", so no jti size can exhaust the cache
// (Section 11.1).
func replayID(proof *Proof) string {
	htu, err := normalizeHTU(proof.URI)
	if err != nil {
		// Verify has compared the normalized htu already.
		htu = proof.URI
	}
	sum := sha256.Sum256([]byte(proof.Thumbprint + "\x00" + htu + "\x00" + proof.ID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// isProofType reports whether typ is dpop+jwt. Media types compare case-insensitively, and a
// typ without "/" stands for application/<typ> (RFC 7515 Section 4.1.9).
func isProofType(typ any) bool {
	s, ok := typ.(string)
	if !ok {
		return false
	}
	s = strings.ToLower(s)
	return s == JWTType || s == "application/"+JWTType
}

type parsedClaims struct {
	ID, Method, URI string
	IssuedAt        time.Time
	ATH, Nonce      string
}

// parseClaims reads the claims of Section 4.2 with exact member names: encoding/json would
// match "HTU" to a field tagged htu, so the payload is read as a map first.
func parseClaims(payload []byte) (parsedClaims, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return parsedClaims{}, proofError("DPoP proof payload is not a JSON object")
	}
	var c parsedClaims
	var ok bool
	if c.ID, ok = stringMember(members, "jti"); !ok || c.ID == "" {
		return c, proofError("DPoP proof has no jti")
	}
	if c.Method, ok = stringMember(members, "htm"); !ok || c.Method == "" {
		return c, proofError("DPoP proof has no htm")
	}
	if c.URI, ok = stringMember(members, "htu"); !ok || c.URI == "" {
		return c, proofError("DPoP proof has no htu")
	}
	iat, ok := members["iat"]
	if !ok {
		return c, proofError("DPoP proof has no iat")
	}
	// A NumericDate may have a fraction (RFC 7519 Section 2). Times outside 1970 to 9999 are
	// refused here rather than overflowing the conversion below.
	var seconds float64
	if err := json.Unmarshal(iat, &seconds); err != nil || seconds < 0 || seconds > maxNumericDate {
		return c, proofError("DPoP proof iat is not a NumericDate")
	}
	whole, fraction := math.Modf(seconds)
	c.IssuedAt = time.Unix(int64(whole), int64(fraction*1e9))
	if _, present := members["ath"]; present {
		if c.ATH, ok = stringMember(members, "ath"); !ok {
			return c, proofError("DPoP proof ath is not a string")
		}
	}
	if _, present := members["nonce"]; present {
		if c.Nonce, ok = stringMember(members, "nonce"); !ok {
			return c, proofError("DPoP proof nonce is not a string")
		}
	}
	return c, nil
}

func stringMember(members map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := members[name]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// checkURI is check 9 of Section 4.3.
func (v *Verifier) checkURI(htu, requestURI string) error {
	want, err := normalizeHTU(requestURI)
	if err != nil {
		// The server's own configuration is wrong, not the proof.
		return fmt.Errorf("dpop: request URI %q: %w", requestURI, err)
	}
	got, err := normalizeHTU(htu)
	if err != nil || got != want {
		return proofError("DPoP proof htu does not match the request URI")
	}
	return nil
}

// checkNonce is check 10 of Section 4.3. A missing or unknown nonce is answered with
// use_dpop_nonce and a fresh nonce (Sections 8, 9).
func (v *Verifier) checkNonce(nonce string) error {
	if v.nonces == nil {
		return nil
	}
	if nonce != "" && v.nonces.Valid(nonce) {
		return nil
	}
	fresh, err := v.nonces.Fresh()
	if err != nil {
		return fmt.Errorf("dpop: nonce source: %w", err)
	}
	description := "DPoP proof has no nonce"
	if nonce != "" {
		description = "DPoP proof nonce is not current"
	}
	return &Error{Code: CodeUseNonce, Description: description, Nonce: fresh}
}

// checkBinding is check 12 of Section 4.3 and the binding of Sections 6, 7.1 and 10.
func checkBinding(proof *Proof, req Request) error {
	if req.AccessToken != "" {
		if req.Thumbprint == "" {
			return &Error{Code: CodeInvalidToken, Description: "access token is not DPoP-bound"}
		}
		if proof.AccessTokenHash == "" {
			return proofError("DPoP proof has no ath")
		}
		if subtle.ConstantTimeCompare([]byte(proof.AccessTokenHash), []byte(AccessTokenHash(req.AccessToken))) != 1 {
			return proofError("DPoP proof ath does not match the access token")
		}
	}
	if req.Thumbprint != "" && subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(req.Thumbprint)) != 1 {
		if req.AccessToken != "" {
			// Figure 16.
			return &Error{Code: CodeInvalidToken, Description: "Invalid DPoP key binding"}
		}
		return proofError("DPoP proof key is not the key the grant is bound to")
	}
	return nil
}
