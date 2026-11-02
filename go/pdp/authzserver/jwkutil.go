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
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// GenerateRandomJwk returns a new P-256 private key as a JWK whose kid is its ThumbprintS256.
func GenerateRandomJwk() (jwk.Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %w", err)
	}
	jwkKey, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create jwk from key: %w", err)
	}

	t, err := ThumbprintS256(jwkKey)
	if err != nil {
		return nil, fmt.Errorf("could not create thumbprint: %w", err)
	}

	if err := jwkKey.Set(jwk.KeyIDKey, t); err != nil {
		return nil, fmt.Errorf("could not set key id: %w", err)
	}

	return jwkKey, nil
}

// ThumbprintS256 returns the base64url-encoded SHA-256 JWK thumbprint of a key (RFC 7638).
func ThumbprintS256(jwk jwk.Key) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("could not create thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// GenerateJwkSet returns a set of num keys from GenerateRandomJwk. The set holds the private keys.
func GenerateJwkSet(num int) (jwk.Set, error) {
	set := jwk.NewSet()
	for range num {
		key, err := GenerateRandomJwk()
		if err != nil {
			return nil, fmt.Errorf("could not generate key: %w", err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("could not add key: %w", err)
		}
	}

	return set, nil
}

// PublicJwkSet returns a set with the public part of every key in set.
func PublicJwkSet(set jwk.Set) (jwk.Set, error) {
	publicSet := jwk.NewSet()
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		publicKey, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("could not get public key: %w", err)
		}
		if err := publicSet.AddKey(publicKey); err != nil {
			return nil, fmt.Errorf("could not add public key: %w", err)
		}
	}
	return publicSet, nil
}
