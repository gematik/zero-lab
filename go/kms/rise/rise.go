package rise

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// KMS is the rise Konnektor Management Service implementation.
type KMS struct {
	cfg        *Config
	HTTPClient *http.Client
}

// New creates a new KMS instance.
func New(opts ...Option) *KMS {
	cfg := &Config{}
	for _, opt := range opts {
		opt(cfg)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	return &KMS{
		cfg:        cfg,
		HTTPClient: client,
	}
}

// Login authenticates with the rise KMS.
func (k *KMS) Login(kmsURL, username, password string) error {
	slog.Info("Logging in to rise KMS", "url", kmsURL, "user", username)

	// Make request to url first so that cookies are set
	reqInit, err := http.NewRequest("GET", kmsURL+"/api/v1/users/current", nil)
	if err != nil {
		return fmt.Errorf("failed to create initial request: %w", err)
	}
	reqInit.Header.Set("X-Requested-With", "RISEHttpRequest")
	reqInit.Header.Set("Referer", kmsURL)

	respInit, err := k.HTTPClient.Do(reqInit)
	if err != nil {
		return fmt.Errorf("failed to make initial request: %w", err)
	}
	io.Copy(io.Discard, respInit.Body)
	respInit.Body.Close()

	loginReq := LoginRequest{
		User:     username,
		Password: password,
	}
	body, err := json.Marshal(loginReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", kmsURL+"/api/v1/auth/login", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	req.Header.Set("Referer", kmsURL)
	req.Header.Set("X-Requested-With", "RISEHttpRequest")

	resp, err := k.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		slog.Error("Login failed", "status", resp.Status, "body", string(bodyBytes), "request_headers", req.Header, "response_headers", resp.Header)
		return fmt.Errorf("login failed with status: %s", resp.Status)
	}

	return nil
}

// GetInfomodel retrieves the information model from the rise KMS.
func (k *KMS) GetInfomodel() (*Infomodell, error) {
	resp, err := k.HTTPClient.Get(k.cfg.URL + "/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get infomodel with status: %s", resp.Status)
	}
	var infomodel Infomodell
	if err := json.NewDecoder(resp.Body).Decode(&infomodel); err != nil {
		return nil, err
	}
	return &infomodel, nil
}
