package nonce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisNonceService struct {
	options Options
	client  redis.UniversalClient
}

func NewRedisNonceService(client redis.UniversalClient, options Options) (Service, error) {
	return &RedisNonceService{
		options: options,
		client:  client,
	}, nil
}

const nonceBits = 256

func (s *RedisNonceService) Get() (string, error) {
	randomBytes := make([]byte, nonceBits/8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(randomBytes)

	ctx := context.Background()
	expiry := time.Duration(s.options.ExpirySeconds) * time.Second
	if err := s.client.Set(ctx, "nonce:"+nonce, "", expiry).Err(); err != nil {
		return "", fmt.Errorf("storing nonce in redis: %w", err)
	}
	return nonce, nil
}

func (s *RedisNonceService) Redeem(nonce string) error {
	ctx := context.Background()

	exists, err := s.client.Exists(ctx, "nonce:"+nonce).Result()
	if err != nil {
		return fmt.Errorf("checking nonce in redis: %w", err)
	}
	if exists == 0 {
		return errors.New("nonce not found")
	}

	if err := s.client.Del(ctx, "nonce:"+nonce).Err(); err != nil {
		return fmt.Errorf("deleting nonce from redis: %w", err)
	}
	return nil
}
