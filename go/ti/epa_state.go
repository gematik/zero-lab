package main

import (
	"encoding/json"
	"fmt"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/ti/state"
)

// Key prefixes / constructors. Scope everything by env so dev/test/ref/prod
// don't collide.
func kvnrProviderKey(env epa.Env, kvnr string) string {
	return fmt.Sprintf("epa:provider-of:%s:%s", env, kvnr)
}

func vauKeysKey(env epa.Env, provider epa.ProviderNumber) string {
	return fmt.Sprintf("epa:vau-keys:%s:%d", env, provider)
}

func certPoolKey(env epa.Env) string {
	return fmt.Sprintf("epa:cert-pool:%s", env)
}

// getJSON reads key from the store and decodes its value into a fresh T. The
// boolean is false on miss (absent or expired).
func getJSON[T any](s state.Store, key string) (T, bool, error) {
	var zero T
	data, ok, err := s.Get(key)
	if err != nil || !ok {
		return zero, ok, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return zero, false, fmt.Errorf("state: decoding %s: %w", key, err)
	}
	return v, true, nil
}

// setJSON encodes v and stores it under key.
func setJSON[T any](s state.Store, key string, v T, opts ...state.SetOption) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("state: encoding %s: %w", key, err)
	}
	return s.Set(key, data, opts...)
}
