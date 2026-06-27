package oidf

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const defaultHTTPTimeout = 30 * time.Second

// transportOrDefault returns http.DefaultTransport when rt is nil, so a decorated client always
// has a concrete base transport to wrap.
func transportOrDefault(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		return http.DefaultTransport
	}
	return rt
}

type OpenidFederation struct {
	fedMasterURL string
	jwks         jwk.Set
	entity       *FederationEntityMetadata
	httpClient   *http.Client
}

type OpenidProvider struct {
	Issuer string
}

func clockWithTolerance(tolerance time.Duration) jwt.ClockFunc {
	return func() time.Time {
		return time.Now().Add(tolerance)
	}
}

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

func NewOpenidFederation(fedMasterURL string, jwks jwk.Set, opts ...Option) (*OpenidFederation, error) {
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
	decorated.Transport = AddApiKeyTransport(transportOrDefault(httpClient.Transport))
	httpClient = &decorated

	es, err := fetchMasterEntityStatement(fedMasterURL, jwks, httpClient)
	if err != nil {
		return nil, err
	}

	if es.Metadata.FederationEntity == nil {
		return nil, fmt.Errorf("no federation entity found in master entity statement")
	}

	return &OpenidFederation{
		fedMasterURL: fedMasterURL,
		jwks:         jwks,
		entity:       es.Metadata.FederationEntity,
		httpClient:   httpClient,
	}, nil
}

func (f *OpenidFederation) FetchIdpList() ([]IdentityProviderInfo, error) {
	r, err := f.httpClient.Get(f.entity.IdpListEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch idp list from '%s': %w", f.entity.IdpListEndpoint, err)
	}
	defer r.Body.Close()

	token, err := jwt.ParseReader(r.Body, jwt.WithKeySet(f.jwks), jwt.WithClock(clockWithTolerance(90*time.Second)))
	if err != nil {
		return nil, err
	}

	var idpEntity any
	if err := token.Get("idp_entity", &idpEntity); err != nil {
		return nil, fmt.Errorf("unable to get idp_entity from token: %w", err)
	}

	return idpEntityToIdpInfo(idpEntity)

}

func fetchMasterEntityStatement(fedMasterURL string, jwks jwk.Set, httpClient *http.Client) (*EntityStatement, error) {
	resp, err := httpClient.Get(fedMasterURL + "/.well-known/openid-federation")
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

	token, err := jwt.ParseReader(resp.Body, jwt.WithKeySet(jwks), jwt.WithClock(clockWithTolerance(90*time.Second)))
	if err != nil {
		return nil, err
	}

	return tokenToEntityStatement(token)
}

func (f *OpenidFederation) fetchAndVerify(url string, jwks jwk.Set) (*EntityStatement, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.httpClient.Do(req)
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

	verified, err := jwt.ParseReader(resp.Body, jwt.WithKeySet(jwks), jwt.WithClock(clockWithTolerance(90*time.Second)))
	if err != nil {
		return nil, err
	}

	return tokenToEntityStatement(verified)
}

// fetches and verifies the entity statement for the given issuer
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

	selfSigned, err := f.fetchAndVerify(iss+"/.well-known/openid-federation", fromMaster.Jwks.Keys)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch entity statement from '%s': %w", iss, err)
	}

	return selfSigned, nil
}

// converts idp_entity claim to array of IdentityProviderInfo
func idpEntityToIdpInfo(idpEntity any) ([]IdentityProviderInfo, error) {
	// serialize the obj to json
	jsonData, err := json.Marshal(idpEntity)
	if err != nil {
		return nil, err
	}

	// deserialize the json to an oidf.Metadata object
	var idpInfo []IdentityProviderInfo
	err = json.Unmarshal(jsonData, &idpInfo)
	if err != nil {
		return nil, err
	}

	return idpInfo, nil
}

func (f *OpenidFederation) FederationMasterURL() string {
	return f.fedMasterURL
}

func (f *OpenidFederation) FetchSignedJwks(op *EntityStatement) (jwk.Set, error) {
	if op.Metadata == nil || op.Metadata.OpenidProvider == nil {
		return nil, fmt.Errorf("no openid provider found in entity statement")
	}

	jwksUrl := op.Metadata.OpenidProvider.SignedJwksUri

	resp, err := f.httpClient.Get(jwksUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %w", jwksUrl, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch jwks from '%s': %s", jwksUrl, resp.Status)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read jwks response body: %w", err)
	}

	jwksBytes, err := jws.Verify(body, jws.WithKeySet(op.Jwks.Keys))
	if err != nil {
		return nil, fmt.Errorf("unable to verify jwks: %w", err)
	}

	jwks, err := jwk.Parse(jwksBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing jwks failed: %w", err)
	}

	return jwks, err
}
