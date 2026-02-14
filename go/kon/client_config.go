package kon

import "time"

// ClientConfig holds client-side behavior settings (timeouts, etc.)
// that are independent of the Konnektor connection configuration (Dotkon).
type ClientConfig struct {
	// ShortTimeout is used for fast operations like GetCards, GetCertificates, SDS loading.
	ShortTimeout time.Duration
	// LongTimeout is used for long-running operations like signing and encryption.
	LongTimeout time.Duration
	// Cache is an optional key-value cache for SOAP responses.
	// When nil (default), all caching is skipped.
	Cache Cache
}

// ClientOption configures a Client.
type ClientOption func(*ClientConfig)

// WithClientConfig applies all settings from the given ClientConfig.
func WithClientConfig(cfg *ClientConfig) ClientOption {
	return func(c *ClientConfig) {
		*c = *cfg
	}
}

// WithCache sets a Cache implementation on the client.
func WithCache(c Cache) ClientOption {
	return func(cfg *ClientConfig) {
		cfg.Cache = c
	}
}

func defaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ShortTimeout: 5 * time.Second,
		LongTimeout:  60 * time.Second,
	}
}
