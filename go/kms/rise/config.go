package rise

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
)

// Config holds the configuration for a KMS instance.
type Config struct {
	URL        string
	Username   string
	Password   string
	HTTPClient *http.Client
}

// Option defines a function that can modify a Config.
type Option func(*Config)

// WithURL sets the URL for the KMS instance.
func WithURL(url string) Option {
	return func(c *Config) {
		c.URL = url
	}
}

// WithUsername sets the username for the KMS instance.
func WithUsername(username string) Option {
	return func(c *Config) {
		c.Username = username
	}
}

// WithPassword sets the password for the KMS instance.
func WithPassword(password string) Option {
	return func(c *Config) {
		c.Password = password
	}
}

// WithHTTPClient sets the HTTP client for the KMS instance.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) {
		c.HTTPClient = client
		if c.HTTPClient.Jar == nil {
			jar, err := cookiejar.New(nil)
			if err != nil {
				panic(fmt.Sprintf("failed to create cookie jar: %v", err))
			}
			c.HTTPClient.Jar = jar
		}

	}
}
