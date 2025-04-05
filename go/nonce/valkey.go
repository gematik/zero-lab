package nonce

import (
	"errors"
	"fmt"

	"crypto/rand"
	"encoding/base64"

	"github.com/valkey-io/valkey-glide/go/api"
)

type ValkeyNonceService struct {
	options Options
	client  api.GlideClientCommands
}

func NewValkeyNonceService(config *api.GlideClientConfiguration, options Options) (Service, error) {
	client, err := api.NewGlideClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating glide client: %w", err)
	}

	return &ValkeyNonceService{
		options: options,
		client:  client,
	}, nil
}

const nonceBits = 256 // Replace with desired number of bits

func (v *ValkeyNonceService) Get() (string, error) {
	randomBytes := make([]byte, nonceBits/8)

	// Generate random bytes
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	// Encode the random bytes as base64 URL without padding
	nonce := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Store the nonce in Valkey
	_, err = v.client.Set("nonce:"+nonce, "")
	if err != nil {
		return "", fmt.Errorf("storing nonce in Valkey: %w", err)
	}
	_, err = v.client.Expire("nonce:"+nonce, v.options.ExpirySeconds) // Expire the nonce after 60 seconds
	if err != nil {
		return "", fmt.Errorf("setting expiry for nonce in Valkey: %w", err)
	}

	return nonce, nil
}

func (v *ValkeyNonceService) Redeem(nonce string) error {
	// Check if the nonce exists in Valkey
	exists, err := v.client.Exists([]string{"nonce:" + nonce})
	if err != nil {
		return fmt.Errorf("checking if nonce exists in Valkey: %w", err)
	}
	if exists == 0 {
		return errors.New("nonce not found")
	}

	// Delete the nonce from Valkey
	num, err := v.client.Del([]string{"nonce:" + nonce})
	if err != nil {
		return fmt.Errorf("deleting nonce from Valkey: %w", err)
	}
	if num == 0 {
		return errors.New("nonce not found")
	}

	return nil
}
