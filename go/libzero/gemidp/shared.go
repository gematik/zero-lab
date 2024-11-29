package gemidp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gematik/zero-lab/go/brainpool"
)

func fetchMetadata(baseURL string, httpClient *http.Client) (*Metadata, error) {
	slog.Debug("Fetching OP metadata", "url", baseURL+"/.well-known/openid-configuration")
	resp, err := httpClient.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading discovery document: %w", err)
	}

	sigJWK, err := extractKeyFromX5CHeader(data)
	if err != nil {
		return nil, fmt.Errorf("extracting signing key: %w", err)
	}

	slog.Debug("Extracted signing key", "key", sigJWK)

	token, err := brainpool.ParseToken(data, brainpool.WithKey(sigJWK))
	if err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	slog.Warn("Certificate of discovery document not verified. Don't trust it in production.", "url", resp.Request.URL.String())

	metadata := new(Metadata)
	err = json.Unmarshal(token.PayloadJson, metadata)
	if err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	slog.Debug("Fetched OP metadata", "metadata", metadata)

	return metadata, nil
}

func extractKeyFromX5CHeader(data []byte) (*brainpool.JSONWebKey, error) {
	parts := strings.Split(string(data), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	var headerStruct struct {
		Kid string   `json:"kid"`
		X5c [][]byte `json:"x5c"`
	}

	err = json.Unmarshal(headerBytes, &headerStruct)
	if err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}

	if len(headerStruct.X5c) == 0 {
		return nil, fmt.Errorf("no certificate found in header")
	}

	if headerStruct.Kid == "" {
		return nil, fmt.Errorf("no kid found in header")
	}

	cert, err := brainpool.ParseCertificate(headerStruct.X5c[0])
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return &brainpool.JSONWebKey{
		Key:          cert.PublicKey,
		KeyID:        headerStruct.Kid,
		Use:          "sig",
		Certificates: []*x509.Certificate{cert},
	}, nil
}

// fetch and parse JWK from the given URI
func fetchKey(uri string) (*brainpool.JSONWebKey, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("fetching JWK: %w", err)
	}
	defer resp.Body.Close()

	key := new(brainpool.JSONWebKey)
	err = json.NewDecoder(resp.Body).Decode(key)
	if err != nil {
		return nil, fmt.Errorf("parsing JWK: %w", err)
	}

	return key, nil
}
