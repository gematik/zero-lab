package kon

import (
	"net/http"
	"time"
)

// ClientConfig holds client-side behavior settings (timeouts, etc.)
// that are independent of the Konnektor connection configuration (Dotkon).
type ClientConfig struct {
	// ShortTimeout is used for fast operations like GetCards, GetCertificates, SDS loading.
	ShortTimeout time.Duration
	// LongTimeout is used for long-running operations like signing and encryption.
	LongTimeout time.Duration
	// HTTPClient is the base client; the Konnektor's mutual-TLS settings are layered onto a copy of
	// it. When nil, a client is built from the Dotkon config with a default timeout.
	HTTPClient *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*ClientConfig)

// WithClientConfig applies all settings from the given ClientConfig.
func WithClientConfig(cfg *ClientConfig) ClientOption {
	return func(c *ClientConfig) {
		*c = *cfg
	}
}

// WithHTTPClient supplies the base HTTP client used to reach the Konnektor.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *ClientConfig) {
		c.HTTPClient = client
	}
}

func defaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ShortTimeout: 5 * time.Second,
		LongTimeout:  60 * time.Second,
	}
}
