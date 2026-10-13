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

const (
	EnvironmentTest Environment = iota
	EnvironmentReference
	EnvironmentProduction
)

type Idp struct {
	environment Environment
	baseURL     string
}

func NewIdp(env Environment, baseUrl string) Idp {
	return Idp{
		environment: env,
		baseURL:     baseUrl,
	}
}

var IdpProduction = NewIdp(EnvironmentProduction, "https://idp.app.ti-dienste.de")
var IdpReference = NewIdp(EnvironmentReference, "https://idp-ref.app.ti-dienste.de")
var IdpTest = NewIdp(EnvironmentTest, "https://idp-test.app.ti-dienste.de")

func GetIdpByEnvironment(env Environment) Idp {
	switch env {
	case EnvironmentProduction:
		return IdpProduction
	case EnvironmentReference:
		return IdpReference
	default:
		return IdpTest
	}
}

func (e *Environment) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	*e = NewEnvironment(s)
	return nil
}

func NewEnvironment(s string) Environment {
	switch s {
	case "tu", "test":
		return EnvironmentTest
	case "ru", "ref":
		return EnvironmentReference
	case "prod", "":
		return EnvironmentProduction
	default:
		return EnvironmentReference
	}
}

func fetchMetadata(baseURL string, httpClient *http.Client) (*Metadata, error) {
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

	slog.Debug("Extracted signing key", "key", sigJWK)

	token, err := josebp.ParseToken(data, josebp.WithKey(sigJWK))
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

func extractKeyFromX5CHeader(data []byte) (*josebp.JSONWebKey, error) {
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

	return &josebp.JSONWebKey{
		Key:          cert.PublicKey,
		KeyID:        headerStruct.Kid,
		Use:          "sig",
		Certificates: []*x509.Certificate{cert},
	}, nil
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
