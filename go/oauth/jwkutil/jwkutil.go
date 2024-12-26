package jwkutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GenerateRandomJwk() (jwk.Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %w", err)
	}
	jwkKey, err := jwk.FromRaw(privateKey)
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
	for i := 0; i < num; i++ {
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
	for iter := set.Iterate(context.Background()); iter.Next(context.Background()); {
		print(set)
		key := iter.Pair().Value.(jwk.Key)
		publicKey, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("could not get public key: %w", err)
		}
		publicSet.AddKey(publicKey)
	}
	return publicSet, nil
}
