package nonce

import (
	"context"
	"errors"
	"fmt"
	"time"

	"crypto/rand"
	"encoding/base64"

	"github.com/valkey-io/valkey-go"
)

type ValkeyNonceService struct {
	options      Options
	valkeyClient valkey.Client
}

func NewValkeyNonceService(valkeyClient valkey.Client, options Options) (Service, error) {

	return &ValkeyNonceService{
		options:      options,
		valkeyClient: valkeyClient,
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
	ctx := context.Background()
	expiryDuration := time.Duration(v.options.ExpirySeconds) * time.Second
	err = v.valkeyClient.Do(ctx, v.valkeyClient.B().Set().Key("nonce:"+nonce).Value("").Ex(expiryDuration).Build()).Error()
	if err != nil {
		return "", fmt.Errorf("storing nonce in Valkey: %w", err)
	}

	return nonce, nil
}

func (v *ValkeyNonceService) Redeem(nonce string) error {
	ctx := context.Background()
	// Check if the nonce exists in Valkey
	cmd := v.valkeyClient.B().Exists().Key("nonce:" + nonce).Build()
	result := v.valkeyClient.Do(ctx, cmd)
	if result.Error() != nil {
		return fmt.Errorf("checking if nonce exists in Valkey: %w", result.Error())
	}
	exists, err := result.AsBool()
	if err != nil {
		return fmt.Errorf("checking if nonce exists in Valkey: %w", err)
	}
	if !exists {
		return errors.New("nonce not found")
	}

	// Delete the nonce from Valkey
	cmd = v.valkeyClient.B().Del().Key("nonce:" + nonce).Build()
	err = v.valkeyClient.Do(ctx, cmd).Error()
	if err != nil {
		return fmt.Errorf("deleting nonce from Valkey: %w", err)
	}

	return nil
}
