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

	"github.com/go-jose/go-jose/v4"
	"github.com/spilikin/go-brainpool"
)

func fetchMetadata(baseURL string, httpClient *http.Client) (*Metadata, error) {
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

	slog.Info("Extracted signing key", "key", sigJWK)

	token, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{jose.BP256R1})
	if err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	metadataBytes, err := token.Verify(sigJWK)
	if err != nil {
		return nil, fmt.Errorf("verifying discovery document: %w", err)
	}

	slog.Warn("Certificate of discovery document not verified. Don't trust it in production.", "url", resp.Request.URL)
	slog.Info("Parsed discovery document", "token", token)

	metadata := new(Metadata)
	err = json.Unmarshal(metadataBytes, metadata)
	if err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	slog.Info("Fetched OP metadata", "metadata", metadata)

	return metadata, nil
}

func extractKeyFromX5CHeader(data []byte) (*jose.JSONWebKey, error) {
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

	return &jose.JSONWebKey{
		Key:          cert.PublicKey,
		KeyID:        headerStruct.Kid,
		Use:          "sig",
		Certificates: []*x509.Certificate{cert},
	}, nil
}

// fetch and parse JWK from the given URI
func fetchKey(uri string) (*jose.JSONWebKey, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("fetching JWK: %w", err)
	}
	defer resp.Body.Close()

	key := new(jose.JSONWebKey)
	err = json.NewDecoder(resp.Body).Decode(key)
	if err != nil {
		return nil, fmt.Errorf("parsing JWK: %w", err)
	}

	return key, nil
}
