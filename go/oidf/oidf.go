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

// Package oidf implements the relying party of the gematik OpenID Federation: its signed entity statement,
// the verified fetches from the federation master, and logins at the federated OpenID providers.
package oidf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	// statementClockTolerance is added to the clock a signed federation document is judged at. Having nbf and iat
	// in the future by that much is tolerated, and exp is met that much earlier.
	statementClockTolerance = 90 * time.Second
)

// federationKeys refuses a key that does not state its alg: the algorithm of a federation document is fixed by the key
// that vouches for it, not left to what the key's type allows.
var federationKeys = oidc.VerifyOptions{RequireKeyAlgorithm: true}

// verifyStatement verifies a signed federation document against keys and checks its lifetime, returning its claims.
func verifyStatement(r io.Reader, keys *jose.JSONWebKeySet) ([]byte, error) {
	signed, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	payload, err := oidc.VerifyJWS(signed, keys, federationKeys)
	if err != nil {
		return nil, err
	}
	if err := oidc.ValidateLifetime(payload, time.Now().Add(statementClockTolerance), 0); err != nil {
		return nil, err
	}
	return payload, nil
}

// transportOrDefault returns http.DefaultTransport when rt is nil, so a decorated client always
// has a concrete base transport to wrap.
func transportOrDefault(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		return http.DefaultTransport
	}
	return rt
}

// OpenidFederation is a client of one federation master, holding the trust anchor that everything fetched from
// the master is verified against.
type OpenidFederation struct {
	fedMasterURL string
	jwks         *jose.JSONWebKeySet
	entity       *FederationEntityMetadata
	httpClient   *http.Client
}

// OpenidProvider names an OpenID provider by its issuer.
type OpenidProvider struct {
	Issuer string
}

// IdentityProviderInfo is one entry of the federation master's IdP list.
type IdentityProviderInfo struct {
	Issuer           string   `json:"iss"`
	LogoURI          string   `json:"logo_uri"`
	OrganizationName string   `json:"organization_name"`
	IsPkv            bool     `json:"pkv"`
	UserType         UserType `json:"user_type_supported"`
}

// Option configures an OpenidFederation.
type Option func(*federationOptions)

type federationOptions struct {
	httpClient *http.Client
}

// WithHTTPClient supplies the base HTTP client; the federation API key is layered onto a copy of it.
// When unset, a client with a default timeout is created.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(o *federationOptions) {
		o.httpClient = httpClient
	}
}

// NewOpenidFederation fetches the master's entity statement from fedMasterURL, verifies it against the trust
// anchor jwks and returns a client of that master. It fails if the statement does not verify or names no
// federation_entity metadata.
func NewOpenidFederation(fedMasterURL string, jwks *jose.JSONWebKeySet, opts ...Option) (*OpenidFederation, error) {
	o := &federationOptions{}
	for _, opt := range opts {
		opt(o)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	// layer the federation API key onto the chosen client without mutating the caller's
	decorated := *httpClient
	decorated.Transport = AddAPIKeyTransport(transportOrDefault(httpClient.Transport))
	httpClient = &decorated

	es, err := fetchMasterEntityStatement(fedMasterURL, jwks, httpClient)
	if err != nil {
		return nil, err
	}

	if es.Metadata.FederationEntity == nil {
		return nil, errors.New("no federation entity found in master entity statement")
	}

	return &OpenidFederation{
		fedMasterURL: fedMasterURL,
		jwks:         jwks,
		entity:       es.Metadata.FederationEntity,
		httpClient:   httpClient,
	}, nil
}

// FetchIdpList fetches the master's IdP list and verifies it against the trust anchor. Each call goes to the
// network.
func (f *OpenidFederation) FetchIdpList() ([]IdentityProviderInfo, error) {
	r, err := f.httpClient.Get(f.entity.IdpListEndpoint) //nolint:gosec // the endpoint comes from the master entity statement, verified against the operator-configured trust anchor
	if err != nil {
		return nil, fmt.Errorf("unable to fetch idp list from '%s': %w", f.entity.IdpListEndpoint, err)
	}
	defer r.Body.Close()

	payload, err := verifyStatement(r.Body, f.jwks)
	if err != nil {
		return nil, err
	}

	var claims struct {
		IdpEntity *[]IdentityProviderInfo `json:"idp_entity"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unable to read idp_entity from token: %w", err)
	}
	if claims.IdpEntity == nil {
		return nil, errors.New("unable to get idp_entity from token: no such claim")
	}

	return *claims.IdpEntity, nil
}

func fetchMasterEntityStatement(fedMasterURL string, jwks *jose.JSONWebKeySet, httpClient *http.Client) (*EntityStatement, error) {
	resp, err := httpClient.Get(fedMasterURL + "/.well-known/openid-federation") //nolint:gosec // fedMasterURL is the operator's fed_master_url, not request input
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("unable to read response body", "error", err)
		} else {
			slog.Error("unable to fetch entity statement", "status", resp.Status, "body", string(body))
		}
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %s", fedMasterURL, resp.Status)
	}

	payload, err := verifyStatement(resp.Body, jwks)
	if err != nil {
		return nil, err
	}

	return parseEntityStatement(payload)
}

func (f *OpenidFederation) fetchAndVerify(url string, jwks *jose.JSONWebKeySet) (*EntityStatement, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil) //nolint:gosec // TASK-182: iss and signed_jwks_uri are not constrained
	if err != nil {
		return nil, err
	}

	resp, err := f.httpClient.Do(req) //nolint:gosec // TASK-182: iss and signed_jwks_uri are not constrained
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var oidcErr Error
		err = json.NewDecoder(resp.Body).Decode(&oidcErr)
		if err != nil {
			return nil, fmt.Errorf("http error %d", resp.StatusCode)
		}
		return nil, &oidcErr
	}

	payload, err := verifyStatement(resp.Body, jwks)
	if err != nil {
		return nil, err
	}

	return parseEntityStatement(payload)
}

// FetchEntityStatement returns the self-signed entity statement of the issuer iss, verified with the keys that
// the master's statement about iss vouches for.
func (f *OpenidFederation) FetchEntityStatement(iss string) (*EntityStatement, error) {
	query := url.Values{}
	query.Add("iss", f.fedMasterURL)
	query.Add("sub", iss)

	url := f.entity.FederationFetchEndpoint + "?" + query.Encode()

	// fetch the entity statement from the fed master first to get the trusted keys
	fromMaster, err := f.fetchAndVerify(url, f.jwks)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", url, err)
	}

	if fromMaster.Jwks == nil {
		return nil, fmt.Errorf("the master's statement about '%s' vouches for no keys", iss)
	}

	selfSigned, err := f.fetchAndVerify(iss+"/.well-known/openid-federation", fromMaster.Jwks.Keys)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", iss, err)
	}

	return selfSigned, nil
}

// FederationMasterURL returns the URL given to NewOpenidFederation.
func (f *OpenidFederation) FederationMasterURL() string {
	return f.fedMasterURL
}

// FetchSignedJwks returns the key set published at op's signed_jwks_uri, verified against the keys of op's
// entity statement, so op has to be a statement FetchEntityStatement verified.
func (f *OpenidFederation) FetchSignedJwks(op *EntityStatement) (*jose.JSONWebKeySet, error) {
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, errors.New("no openid provider found in entity statement")
	}
	if op.Jwks == nil {
		return nil, errors.New("no keys found in entity statement")
	}

	jwksURL := op.Metadata.OpenidProvider.SignedJwksURI

	resp, err := f.httpClient.Get(jwksURL) //nolint:gosec // TASK-182: iss and signed_jwks_uri are not constrained
	if err != nil {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %w", jwksURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %s", jwksURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read jwks response body: %w", err)
	}

	jwksBytes, err := oidc.VerifyJWS(bytes.TrimSpace(body), op.Jwks.Keys, federationKeys)
	if err != nil {
		return nil, fmt.Errorf("unable to verify jwks: %w", err)
	}

	jwks, err := oidc.ParseKeySet(jwksBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing jwks failed: %w", err)
	}

	return jwks, nil
}
