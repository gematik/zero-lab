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

	jwkKey.Set(jwk.KeyIDKey, t)

	return jwkKey, nil
}

func ThumbprintS256(jwk jwk.Key) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("could not create thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func GenerateJwkSet(num int) (jwk.Set, error) {
	set := jwk.NewSet()
	for range num {
		key, err := GenerateRandomJwk()
		if err != nil {
			return nil, fmt.Errorf("could not generate key: %w", err)
		}
		set.AddKey(key)
	}

	return set, nil
}

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
		publicSet.AddKey(publicKey)
	}
	return publicSet, nil
}
