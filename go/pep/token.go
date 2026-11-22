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

package pep

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// minRSAModulusBits refuses RSA keys too short to rely on.
	minRSAModulusBits = 2048
	// maxNumericDate is 9999-12-31T23:59:59Z, the last instant a time claim is read as.
	maxNumericDate = 253402300799
)

// verificationAlgorithms are the JWS algorithms an access token may name. All are asymmetric: none and the HS
// family are absent, so a verification key can never be used as a shared secret.
var verificationAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.EdDSA,
}

// AccessToken is an access token whose signature and claims have been verified.
type AccessToken struct {
	// Payload is the token's claims set as it was signed.
	Payload []byte
}

// Thumbprint is the token's cnf.jkt, the key it is bound to (RFC 9449 Section 6.1), or "" for an unbound token.
// Members are read by their exact names; a member named twice leaves the token unbound.
func (t *AccessToken) Thumbprint() string {
	var members map[string]jsontext.Value
	if json.Unmarshal(t.Payload, &members) != nil {
		return ""
	}
	var cnf map[string]any
	if json.Unmarshal(members["cnf"], &cnf) != nil {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// Bound says the token is sender-constrained: it carries a cnf member (RFC 7800 Section 3.1), whatever its
// confirmation method. A payload that does not decode into members counts as bound, so it is never taken for a
// bearer token.
func (t *AccessToken) Bound() bool {
	var members map[string]jsontext.Value
	if json.Unmarshal(t.Payload, &members) != nil {
		return true
	}
	_, bound := members["cnf"]
	return bound
}

// ParseJWKSet parses a JWK Set (RFC 7517 Section 5), or a single JWK as a set of one. An entry that cannot be
// parsed fails the whole set: the set is the operator's own trust configuration, so a typo must not go unnoticed
// and leave a key out.
func ParseJWKSet(data []byte) (*jose.JSONWebKeySet, error) {
	var members map[string]jsontext.Value
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, fmt.Errorf("JWK Set: %w", err)
	}
	rawKeys, isSet := members["keys"]
	if !isSet {
		key := jose.JSONWebKey{}
		if err := json.Unmarshal(data, &key); err != nil {
			return nil, fmt.Errorf("JWK: %w", err)
		}
		return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}, nil
	}
	set := &jose.JSONWebKeySet{}
	if err := json.Unmarshal(rawKeys, &set.Keys); err != nil {
		return nil, fmt.Errorf("JWK Set: keys: %w", err)
	}
	if set.Keys == nil {
		return nil, errors.New("JWK Set: keys is null")
	}
	return set, nil
}

// maxAccessTokenBytes bounds an access token before anything parses it (server rule 28, limits before work). A
// JWT access token with the claims of RFC 9068 and a cnf member is well below 2 KiB; 16 KiB leaves room for
// the claims a deployment adds and stays far below what a server reads as one header.
const maxAccessTokenBytes = 16 << 10

// maxSessionCookieBytes bounds a session snapshot before anything parses it. A browser keeps at least 4096
// bytes per cookie and need not keep more (RFC 6265 Section 6.1), so a longer value is not one this
// package's snapshot was set as.
const maxSessionCookieBytes = 4096

// checkCompact refuses raw unless it is at most limit bytes and has the compact form of a JWS (RFC 7515
// Section 7.1) or JWE (RFC 7516 Section 7.1): parts segments of base64url characters without padding, each
// with content, except the one at index empty, which has none (the encrypted key of direct encryption, RFC
// 7518 Section 4.5; -1 for none). It runs before the JOSE parser, so that parser only sees input of the
// expected size and shape (server rule 28, bodies).
func checkCompact(raw string, limit, parts, empty int) error {
	if len(raw) > limit {
		return errors.New("token is longer than this package reads")
	}
	part, length := 0, 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '.' {
			if !isBase64URL(raw[i]) {
				return errors.New("token is not in compact form")
			}
			length++
			continue
		}
		if (length == 0) != (part == empty) {
			return errors.New("token is not in compact form")
		}
		part, length = part+1, 0
	}
	if part != parts {
		return errors.New("token is not in compact form")
	}
	return nil
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// verifyJWS verifies the compact JWS raw with keys and returns its payload and its protected typ header.
//
// The token has to name an algorithm of the allowlist and, by kid, the key to verify it with; a token without a
// kid is refused, however few keys the set holds. Only the first key of that kid is used, and it has to fit the
// algorithm: its type and curve, its use if stated and its alg if stated.
func verifyJWS(raw string, keys *jose.JSONWebKeySet) ([]byte, string, error) {
	if keys == nil {
		return nil, "", errors.New("no key set to verify with")
	}
	if err := checkCompact(raw, maxAccessTokenBytes, 3, -1); err != nil {
		return nil, "", err
	}
	parsed, err := jose.ParseSignedCompact(raw, verificationAlgorithms)
	if err != nil {
		return nil, "", &reasonError{reason: "token is no compact JWS of an allowed algorithm", err: err}
	}
	header := parsed.Signatures[0].Protected
	if header.KeyID == "" {
		return nil, "", errors.New("token has no kid")
	}
	named := keys.Key(header.KeyID)
	if len(named) == 0 {
		return nil, "", errors.New("no key with the token's kid")
	}
	key := &named[0]
	if err := keyFits(key, jose.SignatureAlgorithm(header.Algorithm)); err != nil {
		return nil, "", fmt.Errorf("the key of the token's kid: %w", err)
	}
	payload, err := parsed.Verify(key.Key)
	if err != nil {
		return nil, "", err
	}
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	return payload, typ, nil
}

// isAccessTokenType reports whether typ names a JWT access token, at+jwt or application/at+jwt; media types compare
// without case (RFC 9068 Section 4, RFC 7515 Section 4.1.9).
func isAccessTokenType(typ string) bool {
	return strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "application/at+jwt")
}

func keyFits(key *jose.JSONWebKey, alg jose.SignatureAlgorithm) error {
	if key.Use != "" && key.Use != "sig" {
		return errors.New("marked for another use than signatures")
	}
	if key.Algorithm != "" && key.Algorithm != string(alg) {
		return fmt.Errorf("states alg %s, the token names %s", key.Algorithm, alg)
	}
	if !publicKeyFits(key.Key, alg) {
		return fmt.Errorf("a %T cannot verify %s", key.Key, alg)
	}
	return nil
}

// publicKeyFits refuses private and symmetric keys along with keys of the wrong type: a key set is public material.
func publicKeyFits(key any, alg jose.SignatureAlgorithm) bool {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch alg {
		case jose.ES256:
			return k.Curve == elliptic.P256()
		case jose.ES384:
			return k.Curve == elliptic.P384()
		case jose.ES512:
			return k.Curve == elliptic.P521()
		}
	case *rsa.PublicKey:
		switch alg {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return k.N.BitLen() >= minRSAModulusBits
		}
	case ed25519.PublicKey:
		return alg == jose.EdDSA
	}
	return false
}

// reasonError refuses a token by a fixed reason. A decoder's message quotes member names and values, here those of a
// token, and error text ends up in logs (servers.md rule 14); the decoder's error stays reachable through errors.Is
// and errors.As, so a caller can still tell why.
type reasonError struct {
	reason string
	err    error
}

func (e *reasonError) Error() string { return e.reason }

func (e *reasonError) Unwrap() error { return e.err }

// validateClaims checks the payload of a verified token: its registered claims have their types, its exp, nbf and
// iat those it has hold at now, and when resource is set the aud names it. Members are read by their exact names, so
// "EXP" is no expiry, and a member named twice or a string that is not UTF-8 refuses the token (server rule 28).
func validateClaims(payload []byte, now time.Time, skew time.Duration, resource string) error {
	if skew < 0 {
		return errors.New("acceptable skew must not be negative")
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(payload, &members); err != nil {
		return &reasonError{reason: "token claims: do not decode", err: err}
	}
	if members == nil {
		return errors.New("token claims: not an object")
	}
	for _, name := range []string{"iss", "sub", "jti"} {
		if raw, ok := members[name]; ok {
			if _, err := stringClaim(raw); err != nil {
				return fmt.Errorf("token claim %s: %w", name, err)
			}
		}
	}
	var audience []string
	if raw, ok := members["aud"]; ok {
		var err error
		if audience, err = audienceClaim(raw); err != nil {
			return fmt.Errorf("token claim aud: %w", err)
		}
	}
	dates := make(map[string]time.Time, 3)
	for _, name := range []string{"exp", "nbf", "iat"} {
		if raw, ok := members[name]; ok {
			date, err := numericDateClaim(raw)
			if err != nil {
				return fmt.Errorf("token claim %s: %w", name, err)
			}
			dates[name] = date
		}
	}
	// RFC 7519 Section 4.1.4 refuses "on or after" exp. A fractional exp counts from its whole second, so a token
	// cannot extend its life by a fraction past what a verifier comparing whole seconds allows.
	if exp, ok := dates["exp"]; ok && !now.Before(exp.Truncate(time.Second).Add(skew)) {
		return errors.New("token is expired")
	}
	if nbf, ok := dates["nbf"]; ok && now.Before(nbf.Add(-skew)) {
		return errors.New("token is not yet valid")
	}
	if iat, ok := dates["iat"]; ok && now.Before(iat.Add(-skew)) {
		return errors.New("token is issued in the future")
	}
	if resource != "" && !slices.Contains(audience, resource) {
		return errors.New("token audience does not name the resource")
	}
	return nil
}

func stringClaim(raw jsontext.Value) (string, error) {
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", &reasonError{reason: "is no string", err: err}
	}
	if value == nil {
		return "", errors.New("is null")
	}
	return *value, nil
}

// audienceClaim reads the single string or array of strings RFC 7519 Section 4.1.3 allows.
func audienceClaim(raw jsontext.Value) ([]string, error) {
	if single, err := stringClaim(raw); err == nil {
		return []string{single}, nil
	}
	var list []*string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, &reasonError{reason: "is no string or array of strings", err: err}
	}
	if list == nil {
		return nil, errors.New("is null")
	}
	audience := make([]string, 0, len(list))
	for _, entry := range list {
		if entry == nil {
			return nil, errors.New("holds null")
		}
		audience = append(audience, *entry)
	}
	return audience, nil
}

func numericDateClaim(raw jsontext.Value) (time.Time, error) {
	var seconds *float64
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return time.Time{}, &reasonError{reason: "is no number", err: err}
	}
	if seconds == nil {
		return time.Time{}, errors.New("is null")
	}
	if math.Abs(*seconds) > maxNumericDate {
		return time.Time{}, errors.New("is out of range")
	}
	whole, fraction := math.Modf(*seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))), nil
}
