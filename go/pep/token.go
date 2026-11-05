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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
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
// Members are read by their exact names, since encoding/json would match a struct field case-insensitively.
func (t *AccessToken) Thumbprint() string {
	var members map[string]json.RawMessage
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

// ParseJWKSet parses a JWK Set (RFC 7517 Section 5), or a single JWK as a set of one. An entry that cannot be
// parsed fails the whole set: the set is the operator's own trust configuration, so a typo must not go unnoticed
// and leave a key out.
func ParseJWKSet(data []byte) (*jose.JSONWebKeySet, error) {
	var members map[string]json.RawMessage
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

// verifyJWS verifies the compact JWS raw with keys and returns its payload.
//
// The token has to name an algorithm of the allowlist and, by kid, the key to verify it with; a token without a
// kid is refused, however few keys the set holds. Only the first key of that kid is used, and it has to fit the
// algorithm: its type and curve, its use if stated and its alg if stated.
func verifyJWS(raw string, keys *jose.JSONWebKeySet) ([]byte, error) {
	if keys == nil {
		return nil, errors.New("no key set to verify with")
	}
	parsed, err := jose.ParseSignedCompact(raw, verificationAlgorithms)
	if err != nil {
		return nil, err
	}
	header := parsed.Signatures[0].Protected
	if header.KeyID == "" {
		return nil, errors.New("token has no kid")
	}
	named := keys.Key(header.KeyID)
	if len(named) == 0 {
		return nil, fmt.Errorf("no key with kid %q", header.KeyID)
	}
	key := &named[0]
	if err := keyFits(key, jose.SignatureAlgorithm(header.Algorithm)); err != nil {
		return nil, fmt.Errorf("key %q: %w", header.KeyID, err)
	}
	return parsed.Verify(key.Key)
}

func keyFits(key *jose.JSONWebKey, alg jose.SignatureAlgorithm) error {
	if key.Use != "" && key.Use != "sig" {
		return fmt.Errorf("marked use=%q, not for signatures", key.Use)
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

// validateClaims checks the payload of a verified token: its registered claims have their types, its exp, nbf and
// iat those it has hold at now, and when resource is set the aud names it. Members are read by their exact names,
// since encoding/json would match a struct field case-insensitively and take "EXP" for the expiry.
func validateClaims(payload []byte, now time.Time, skew time.Duration, resource string) error {
	if skew < 0 {
		return errors.New("acceptable skew must not be negative")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return fmt.Errorf("token claims: %w", err)
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

func stringClaim(raw json.RawMessage) (string, error) {
	var value *string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	if value == nil {
		return "", errors.New("is null")
	}
	return *value, nil
}

// audienceClaim reads the single string or array of strings RFC 7519 Section 4.1.3 allows.
func audienceClaim(raw json.RawMessage) ([]string, error) {
	if single, err := stringClaim(raw); err == nil {
		return []string{single}, nil
	}
	var list []*string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
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

func numericDateClaim(raw json.RawMessage) (time.Time, error) {
	var seconds *float64
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return time.Time{}, err
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
