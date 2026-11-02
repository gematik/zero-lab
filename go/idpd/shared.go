// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package idpd

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/brainpool/josebp"
)

const defaultHTTPTimeout = 30 * time.Second

// defaultUserAgent is sent when ClientConfig.UserAgent is empty: the gematik IDP-Dienst rejects requests
// without a User-Agent ("User Agent fehlt").
const defaultUserAgent = "zero-lab"

// transportOrDefault returns http.DefaultTransport when rt is nil, so a decorated client always
// has a concrete base transport to wrap.
func transportOrDefault(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		return http.DefaultTransport
	}
	return rt
}

// Environment of the gematik IDP-Dienst
type Environment int

// The instances of the IDP-Dienst: test (TU), reference (RU) and production (PU).
const (
	// EnvironmentUnset is what a missing or unknown name yields, and no client starts with it: the
	// environment decides which anchors are trusted (IDPV-006).
	EnvironmentUnset Environment = iota
	EnvironmentTest
	EnvironmentReference
	EnvironmentProduction
)

// IDP names an instance of the IDP-Dienst: its environment and base URL.
type IDP struct {
	environment Environment
	baseURL     string
}

// NewIDP names the instance of the IDP-Dienst at baseURL.
func NewIDP(env Environment, baseURL string) IDP {
	return IDP{
		environment: env,
		baseURL:     baseURL,
	}
}

// The well-known instances of the IDP-Dienst.
var (
	IDPProduction = NewIDP(EnvironmentProduction, "https://idp.app.ti-dienste.de")
	IDPReference  = NewIDP(EnvironmentReference, "https://idp-ref.app.ti-dienste.de")
	IDPTest       = NewIDP(EnvironmentTest, "https://idp-test.app.ti-dienste.de")
)

// GetIDPByEnvironment returns the well-known instance of env.
func GetIDPByEnvironment(env Environment) IDP {
	switch env {
	case EnvironmentProduction:
		return IDPProduction
	case EnvironmentReference:
		return IDPReference
	default:
		return IDPTest
	}
}

// UnmarshalYAML reads an Environment by its name, as NewEnvironment does, so an unknown name is not an error.
func (e *Environment) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	*e = NewEnvironment(s)
	return nil
}

// NewEnvironment maps a name to its Environment: "tu" or "test", "ru" or "ref", "prod" or nothing. Any other
// name is EnvironmentUnset, which refuses to start rather than guess.
func NewEnvironment(s string) Environment {
	switch s {
	case "tu", "test":
		return EnvironmentTest
	case "ru", "ref":
		return EnvironmentReference
	case "prod", "":
		return EnvironmentProduction
	default:
		return EnvironmentUnset
	}
}

func fetchMetadata(baseURL string, httpClient *http.Client, trust CertificateTrust) (*Metadata, error) {
	slog.Debug("Fetching OP metadata", "url", baseURL+"/.well-known/openid-configuration")
	resp, err := httpClient.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp.StatusCode, resp.Body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading discovery document: %w", err)
	}

	sigJWK, err := extractKeyFromX5CHeader(data)
	if err != nil {
		return nil, fmt.Errorf("extracting signing key: %w", err)
	}

	if err := trust.Check(context.Background(), DiscoverySigner, sigJWK.Certificates); err != nil {
		return nil, fmt.Errorf("discovery document: %w", err)
	}

	token, err := josebp.ParseToken(data, josebp.WithKey(sigJWK))
	if err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	metadata := new(Metadata)
	err = json.Unmarshal(token.PayloadJSON, metadata)
	if err != nil {
		return nil, fmt.Errorf("parsing discovery document: %w", err)
	}

	slog.Debug("Fetched OP metadata", "metadata", metadata)

	return metadata, nil
}

func extractKeyFromX5CHeader(data []byte) (*josebp.JSONWebKey, error) {
	parts := strings.Split(string(data), ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
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
		return nil, errors.New("no certificate found in header")
	}

	if headerStruct.Kid == "" {
		return nil, errors.New("no kid found in header")
	}

	certs := make([]*x509.Certificate, 0, len(headerStruct.X5c))
	for _, der := range headerStruct.X5c {
		cert, err := brainpool.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return &josebp.JSONWebKey{
		Key:          certs[0].PublicKey,
		KeyID:        headerStruct.Kid,
		Use:          "sig",
		Certificates: certs,
	}, nil
}

// fetchSigningKey returns the key that signs challenges and tokens, once its certificate is trusted. The
// JWK must carry that certificate and the same key, or the check would say nothing about the key (IDPV-002).
func fetchSigningKey(uri string, httpClient *http.Client, trust CertificateTrust) (*josebp.JSONWebKey, error) {
	key, err := fetchKey(uri, httpClient)
	if err != nil {
		return nil, err
	}
	if len(key.CertificatesRaw) == 0 {
		return nil, fmt.Errorf("%s: no x5c: the key's certificate is unknown", TokenSigner)
	}
	certs := make([]*x509.Certificate, 0, len(key.CertificatesRaw))
	for _, der := range key.CertificatesRaw {
		cert, err := brainpool.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: x5c: %w", TokenSigner, err)
		}
		certs = append(certs, cert)
	}
	public, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an EC key", TokenSigner)
	}
	certified, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(certified) {
		return nil, fmt.Errorf("%s: the x5c certificate carries another key than the JWK", TokenSigner)
	}
	if err := trust.Check(context.Background(), TokenSigner, certs); err != nil {
		return nil, err
	}
	return key, nil
}

// fetchEncryptionKey returns the key the signed challenge is encrypted to. The IDP-Dienst publishes it
// without a certificate, so there is nothing to verify: its address comes from the verified discovery
// document and TLS carries it, as in ti-idpd (IDPV-004). What it can be is checked.
func fetchEncryptionKey(uri string, httpClient *http.Client) (*ecdsa.PublicKey, error) {
	key, err := fetchKey(uri, httpClient)
	if err != nil {
		return nil, err
	}
	public, ok := key.Key.(*ecdsa.PublicKey)
	if !ok || key.Use != "enc" || public.Curve != brainpool.P256r1() {
		return nil, errors.New("puk_idp_enc: not a brainpoolP256r1 key for encryption")
	}
	return public, nil
}

// fetch and parse JWK from the given URI
func fetchKey(uri string, httpClient *http.Client) (*josebp.JSONWebKey, error) {
	resp, err := httpClient.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("fetching JWK: %w", err)
	}
	defer resp.Body.Close()

	key := new(josebp.JSONWebKey)
	err = json.NewDecoder(resp.Body).Decode(key)
	if err != nil {
		return nil, fmt.Errorf("parsing JWK: %w", err)
	}

	return key, nil
}
