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

package authzserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// GenerateRandomJwk returns a new P-256 private key as a JWK whose kid is its ThumbprintS256.
func GenerateRandomJwk() (*jose.JSONWebKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %w", err)
	}
	key := &jose.JSONWebKey{Key: privateKey}
	t, err := ThumbprintS256(key)
	if err != nil {
		return nil, err
	}
	key.KeyID = t
	return key, nil
}

// ThumbprintS256 returns the base64url-encoded SHA-256 JWK thumbprint of a key (RFC 7638).
func ThumbprintS256(key *jose.JSONWebKey) (string, error) {
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("could not create thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// GenerateJwkSet returns a set of num keys from GenerateRandomJwk. The set holds the private keys.
func GenerateJwkSet(num int) (*jose.JSONWebKeySet, error) {
	set := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for range num {
		key, err := GenerateRandomJwk()
		if err != nil {
			return nil, fmt.Errorf("could not generate key: %w", err)
		}
		set.Keys = append(set.Keys, *key)
	}

	return set, nil
}

// PublicKey returns the public part of key. A symmetric key has none, and it is an error: it must not end up in a
// document meant to be public.
func PublicKey(key *jose.JSONWebKey) (*jose.JSONWebKey, error) {
	public := key.Public()
	if !public.Valid() {
		return nil, errors.New("the key has no public part")
	}
	return &public, nil
}

// PublicJwkSet returns a set with the public part of every key in set.
func PublicJwkSet(set *jose.JSONWebKeySet) (*jose.JSONWebKeySet, error) {
	publicSet := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(set.Keys))}
	for i := range set.Keys {
		public, err := PublicKey(&set.Keys[i])
		if err != nil {
			return nil, fmt.Errorf("could not get public key: %w", err)
		}
		publicSet.Keys = append(publicSet.Keys, *public)
	}
	return publicSet, nil
}
