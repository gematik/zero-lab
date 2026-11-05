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

package openid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-jose/go-jose/v4"
)

const (
	// maxKeysInSet bounds the work a key set can cause when it is parsed.
	maxKeysInSet = 1000
	// minRSAModulusBits refuses RSA keys too short to rely on.
	minRSAModulusBits = 2048
)

// verificationAlgorithms are the JWS algorithms a token may name. All are asymmetric: none and the HS family are
// absent, so a verification key can never be used as a shared secret.
var verificationAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.EdDSA,
}

// ParseKey parses one JWK (RFC 7517). A key that is not on its curve, an EC private key whose d is not the private half
// of its x and y, or an RSA key below 2048 bits is refused.
func ParseKey(data []byte) (*jose.JSONWebKey, error) {
	key := new(jose.JSONWebKey)
	if err := json.Unmarshal(data, key); err != nil {
		return nil, err
	}
	var modulusBits int
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		modulusBits = k.N.BitLen()
	case *rsa.PrivateKey:
		modulusBits = k.N.BitLen()
	case *ecdsa.PrivateKey:
		if err := checkECKeyPair(k); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return key, nil
	}
	if modulusBits < minRSAModulusBits {
		return nil, fmt.Errorf("RSA key of %d bits, at least %d are required", modulusBits, minRSAModulusBits)
	}
	return key, nil
}

// checkECKeyPair derives the public point from d, which go-jose does not: it reads d and the point independently.
func checkECKeyPair(key *ecdsa.PrivateKey) error {
	private, err := key.ECDH()
	if err != nil {
		return errors.New("EC private key: not usable on its curve")
	}
	public, err := key.PublicKey.ECDH()
	if err != nil {
		return errors.New("EC private key: the public point is not usable on its curve")
	}
	if !private.PublicKey().Equal(public) {
		return errors.New("EC private key: d does not match x and y")
	}
	return nil
}

// ParseKeySet parses a JWK Set (RFC 7517 section 5), or a single JWK as a set of one. Members other than keys are
// ignored, so the payload of a signed JWKS parses too.
//
// RFC 7517 section 5: an entry that cannot be understood is left out rather than failing the set, since a provider
// may publish kinds of keys this package does not know beside the ones it signs with. An entry left out is never
// trusted. A set whose entries are all unusable is an error; an empty one is not.
func ParseKeySet(data []byte) (*jose.JSONWebKeySet, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, fmt.Errorf("JWK Set: %w", err)
	}
	rawKeys, isSet := members["keys"]
	if !isSet {
		key, err := ParseKey(data)
		if err != nil {
			return nil, fmt.Errorf("JWK: %w", err)
		}
		return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*key}}, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(rawKeys, &entries); err != nil {
		return nil, fmt.Errorf("JWK Set: keys: %w", err)
	}
	if entries == nil {
		return nil, errors.New("JWK Set: keys is null")
	}
	if len(entries) > maxKeysInSet {
		return nil, fmt.Errorf("JWK Set: %d keys, at most %d are accepted", len(entries), maxKeysInSet)
	}
	set := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(entries))}
	var lastErr error
	for i, entry := range entries {
		key, err := ParseKey(entry)
		if err != nil {
			slog.Warn("leaving out a JWK that cannot be used", "index", i, "error", err)
			lastErr = err
			continue
		}
		set.Keys = append(set.Keys, *key)
	}
	if len(entries) > 0 && len(set.Keys) == 0 {
		return nil, fmt.Errorf("JWK Set: no usable key: %w", lastErr)
	}
	return set, nil
}

// VerifyOptions is what a verifier asks of the keys it uses, beyond fitting the token's algorithm.
type VerifyOptions struct {
	// RequireKeyAlgorithm refuses keys that do not state their alg. A trust anchor and an authorization server's own
	// keys have to, while OpenID providers such as Entra ID and T-Systems' federation members publish keys without one.
	RequireKeyAlgorithm bool
}

// VerifyJWS verifies the compact JWS raw with keys and returns its payload; the claims are the caller's to check.
//
// The token has to name an algorithm of the allowlist, and a key it can name by kid has to fit that algorithm: its
// type and curve, its use if stated and its alg if stated. RFC 7515 section 4.1.1 makes alg mandatory, so a token
// without one is refused, never tried against what the key might do. With a kid only the first key of that kid is
// used. A token without a kid is refused: a key set must say which key it means.
func VerifyJWS(raw []byte, keys *jose.JSONWebKeySet, options VerifyOptions) ([]byte, error) {
	if keys == nil {
		return nil, errors.New("no key set to verify with")
	}
	return verifyJWS(string(raw), func(string) (*jose.JSONWebKeySet, error) { return keys, nil }, options)
}

func verifyJWS(raw string, keysFor func(kid string) (*jose.JSONWebKeySet, error), options VerifyOptions) ([]byte, error) {
	parsed, err := jose.ParseSignedCompact(raw, verificationAlgorithms)
	if err != nil {
		return nil, err
	}
	header := parsed.Signatures[0].Protected
	alg := jose.SignatureAlgorithm(header.Algorithm)

	keys, err := keysFor(header.KeyID)
	if err != nil {
		return nil, err
	}

	candidates, err := candidateKeys(keys, header.KeyID, alg, options)
	if err != nil {
		return nil, err
	}
	for i := range candidates {
		if payload, err := parsed.Verify(candidates[i].Key); err == nil {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("signature does not verify with %d candidate key(s)", len(candidates))
}

func candidateKeys(keys *jose.JSONWebKeySet, kid string, alg jose.SignatureAlgorithm, options VerifyOptions) ([]jose.JSONWebKey, error) {
	if kid != "" {
		named := keys.Key(kid)
		if len(named) == 0 {
			return nil, fmt.Errorf("no key with kid %q", kid)
		}
		if err := keyFits(&named[0], alg, options); err != nil {
			return nil, fmt.Errorf("key %q: %w", kid, err)
		}
		return named[:1], nil
	}
	return nil, errors.New("token has no kid")
}

func keyFits(key *jose.JSONWebKey, alg jose.SignatureAlgorithm, options VerifyOptions) error {
	if key.Use != "" && key.Use != "sig" {
		return fmt.Errorf("marked use=%q, not for signatures", key.Use)
	}
	switch {
	case key.Algorithm == "":
		if options.RequireKeyAlgorithm {
			return errors.New("states no alg")
		}
	case key.Algorithm != string(alg):
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
			return true
		}
	case ed25519.PublicKey:
		return alg == jose.EdDSA
	}
	return false
}
