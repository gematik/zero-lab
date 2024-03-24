package oidf

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

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
	LogoUri          string   `json:"logo_uri"`
	OrganizationName string   `json:"organization_name"`
	IsPkv            bool     `json:"pkv"`
	UserType         UserType `json:"user_type_supported"`
}

func NewOpenidFederation(fedMasterURL string, jwks jwk.Set) (*OpenidFederation, error) {
	es, err := fetchMasterEntityStatement(fedMasterURL, jwks)
	if err != nil {
		return nil, err
	}

	if es.Metadata.FederationEntity == nil {
		return nil, fmt.Errorf("no federation entity found in master entity statement")
	}

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: util.AddApiKeyTransport(http.DefaultTransport),
	}

	return &OpenidFederation{
		fedMasterURL: fedMasterURL,
		jwks:         jwks,
		entity:       es.Metadata.FederationEntity,
		httpClient:   httpClient,
	}, nil
}

func (f *OpenidFederation) ListIdpUrls() ([]IdentityProviderInfo, error) {
	r, err := f.httpClient.Get(f.entity.IdpListEndpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch idp list from '%s': %w", f.entity.IdpListEndpoint, err)
	}
	defer r.Body.Close()

	token, err := jwt.ParseReader(r.Body, jwt.WithKeySet(f.jwks), jwt.WithClock(clockWithTolerance(90*time.Second)))
	if err != nil {
		return nil, err
	}

	return idpEntityToIdpInfo(token.PrivateClaims()["idp_entity"])

}

func fetchMasterEntityStatement(fedMasterURL string, jwks jwk.Set) (*EntityStatement, error) {
	resp, err := http.Get(fedMasterURL + "/.well-known/openid-federation")
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(resp.Status)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var oidcErr Error
		err = json.NewDecoder(resp.Body).Decode(&oidcErr)
		if err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
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

	// fetch the entity statement for the fed master first to get the keys
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

// converts the metadata template to an oidf.Metadata object
func templateToMetadata(template map[string]interface{}) (*Metadata, error) {
	// serialize the template to json
	jsonData, err := json.Marshal(template)
	if err != nil {
		return nil, err
	}

	// deserialize the json to an oidf.Metadata object
	var metadata Metadata
	err = json.Unmarshal(jsonData, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, nil
}

// converts idp_entity claim to array of IdentityProviderInfo
func idpEntityToIdpInfo(idpEntity interface{}) ([]IdentityProviderInfo, error) {
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
