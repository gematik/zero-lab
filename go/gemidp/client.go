package gemidp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
)

func init() {
	jwa.RegisterSignatureAlgorithm(jwa.NewSignatureAlgorithm(
		brainpool.AlgorithmNameBP256R1,
	))
}

// OpenID Connect metadata of the gematik IDP-Dienst
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	SigningKeyURI                     string   `json:"uri_puk_idp_sig"`
	EncryptionKeyURI                  string   `json:"uri_puk_idp_enc"`
}

// Payload of the token key sent from the client to the gematik IDP-Dienst
// to encrypt the token(s) when exchanging the authorization code
type TokenKeyPayload struct {
	TokenKey     string `json:"token_key"`
	CodeVerifier string `json:"code_verifier"`
}

// ClientConfig of the gematik IDP-Dienst client
type ClientConfig struct {
	Environment       Environment `yaml:"environment"`
	BaseURL           string      `yaml:"base_url,omitempty"`
	Name              string      `yaml:"name"`
	LogoURI           string      `yaml:"logo_uri"`
	ClientID          string      `yaml:"client_id"`
	RedirectURI       string      `yaml:"redirect_uri"`
	Scopes            []string    `yaml:"scopes"`
	AuthenticatorMode bool        `yaml:"authenticator_mode"`
	UserAgent         string      `yaml:"user_agent"`
}

type Client struct {
	config      ClientConfig
	Environment Environment
	Idp         Idp
	Metadata    Metadata
	baseURL     string
	httpClient  *http.Client
}

func NewClientFromConfig(config ClientConfig) (*Client, error) {
	if config.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}

	if config.RedirectURI == "" {
		return nil, fmt.Errorf("redirect URI is required")
	}

	if len(config.Scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}

	var idp Idp
	if config.BaseURL != "" {
		idp = NewIdp(config.Environment, config.BaseURL)
	} else {
		idp = GetIdpByEnvironment(config.Environment)
	}

	baseURL := idp.baseURL

	httpClient := &http.Client{
		Transport: &transportAddUserAgent{http.DefaultTransport, config.UserAgent},
	}

	metadata, err := fetchMetadata(baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}

	return &Client{
		config:      config,
		Environment: config.Environment,
		Idp:         idp,
		Metadata:    *metadata,
		baseURL:     baseURL,
		httpClient:  httpClient,
	}, nil
}

func (c *Client) AuthenticationURL(state, nonce, verifier string, options ...oidc.Option) (string, error) {
	redirectURI := c.config.RedirectURI
	for _, opt := range options {
		switch o := opt.(type) {
		case oidc.WithAlternateRedirectURI:
			redirectURI = string(o)
		}
	}
	if c.config.AuthenticatorMode {
		return c.authenticationURLAuthenticator(state, nonce, verifier, redirectURI)
	}

	return c.authenticationURLDirect(state, nonce, verifier, redirectURI)
}

func (c *Client) authenticationURLDirect(state, nonce, verifier, redirectURI string) (string, error) {
	if redirectURI == "" {
		redirectURI = c.config.RedirectURI
	}
	codeChallenge := oauth2.S256ChallengeFromVerifier(verifier)
	query := url.Values{}
	query.Add("client_id", c.config.ClientID)
	query.Add("redirect_uri", redirectURI)
	query.Add("response_type", "code")
	query.Add("scope", strings.Join(c.config.Scopes, " "))
	query.Add("state", state)
	query.Add("nonce", nonce)
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", "S256")

	slog.Info("Using OP AuthorizationEndpoint", "url", c.Metadata.AuthorizationEndpoint)

	return fmt.Sprintf("%s?%s", c.Metadata.AuthorizationEndpoint, query.Encode()), nil
}

func (c *Client) authenticationURLAuthenticator(state, nonce, verifier, redirectURI string) (string, error) {
	authURL, err := c.authenticationURLDirect(state, nonce, verifier, redirectURI)
	if err != nil {
		return "", err
	}

	challengePath, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("parsing challenge path: %w", err)
	}

	// TODO: make selection of SMC-B / HBA configurable
	challengePath.RawQuery = challengePath.RawQuery + "&cardType=SMC-B&callback=DIRECT"

	query := url.Values{
		"challenge_path": {challengePath.String()},
	}

	return "authenticator://?" + query.Encode(), nil
}

func (c *Client) ExchangeForIdentity(code, verifier string, options ...oidc.Option) (*oidc.TokenResponse, error) {
	redirectURI := c.config.RedirectURI
	for _, opt := range options {
		switch o := opt.(type) {
		case oidc.WithAlternateRedirectURI:
			redirectURI = string(o)
		}
	}
	// 32 bytes random key to encrypt the token
	tokenKeyBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, tokenKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("generating token key: %w", err)
	}

	idpEncKey, err := fetchKey(c.Metadata.EncryptionKeyURI)
	if err != nil {
		return nil, fmt.Errorf("fetching challenge encryption key: %w", err)
	}

	tokenKeyPayload := TokenKeyPayload{
		TokenKey:     base64.RawURLEncoding.EncodeToString(tokenKeyBytes),
		CodeVerifier: verifier,
	}

	tokenKeyPayloadBytes, err := json.Marshal(tokenKeyPayload)
	if err != nil {
		return nil, fmt.Errorf("marshalling token key payload: %w", err)
	}

	slog.Info("Token key payload", "payload", tokenKeyPayload)

	encryptedTokenKeySerialized, err := brainpool.NewJWEBuilder().
		Plaintext(tokenKeyPayloadBytes).
		EncryptECDHES(idpEncKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting token key payload: %w", err)
	}

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("code", code)
	params.Set("key_verifier", string(encryptedTokenKeySerialized))

	slog.Info("Exchanging code for token", "url", c.Metadata.TokenEndpoint, "params", params)

	resp, err := c.httpClient.PostForm(c.Metadata.TokenEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp.StatusCode, resp.Body)
	}

	tokenResponse, err := unmarshalTokenResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	slog.Debug("Token response", "response", tokenResponse)

	if tokenResponse.IDTokenRaw != "" {
		if tokenResponse.IDTokenRaw, err = decryptToken(tokenResponse.IDTokenRaw, tokenKeyBytes); err != nil {
			return nil, fmt.Errorf("decrypting ID token: %w", err)
		}
		if tokenResponse.IDToken, err = c.parseIDToken(tokenResponse); err != nil {
			return nil, fmt.Errorf("parsing ID token: %w", err)
		}
	}

	if tokenResponse.AccessToken != "" {
		if tokenResponse.AccessToken, err = decryptToken(tokenResponse.AccessToken, tokenKeyBytes); err != nil {
			return nil, fmt.Errorf("decrypting access token: %w", err)
		}
	}

	return tokenResponse, nil
}

func decryptToken(token string, key []byte) (string, error) {

	plaintext, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.DIRECT(), key))
	if err != nil {
		return "", fmt.Errorf("decrypting token: %w", err)
	}

	njwt := new(Njwt)
	err = json.Unmarshal(plaintext, njwt)
	if err != nil {
		return "", fmt.Errorf("parsing NJWT: %w", err)
	}

	return njwt.Njwt, nil
}

func (c *Client) parseIDToken(response *oidc.TokenResponse) (jwt.Token, error) {
	key, err := fetchKey(c.Metadata.SigningKeyURI)
	if err != nil {
		return nil, fmt.Errorf("fetching signing key: %w", err)
	}

	// check signature using the brainpool enabled library
	_, err = brainpool.ParseToken([]byte(response.IDTokenRaw), brainpool.WithKey(key))
	if err != nil {
		return nil, fmt.Errorf("parsing ID token: %w", err)
	}

	// parse the token using the jwx library, after we verified the brainpool signature
	// since the token signature is already verified, we can skip the verification step
	token, err := jwt.ParseString(
		response.IDTokenRaw,
		jwt.WithAcceptableSkew(time.Duration(5*time.Minute)), // allow 5 minutes skew
		jwt.WithVerify(false), // skip verification since we already verified the token before
		jwt.WithIssuer(c.Metadata.Issuer),
		jwt.WithAudience(c.config.ClientID),
		jwt.WithRequiredClaim("nonce"),
		jwt.WithRequiredClaim("exp"),
	)

	if err != nil {
		return nil, fmt.Errorf("unable to parse ID token: %w", err)
	}

	return token, nil
}

func (c *Client) Issuer() string {
	return c.Metadata.Issuer
}

func (c *Client) ClientID() string {
	return c.config.ClientID
}

func (c *Client) Name() string {
	return c.config.Name
}

func (c *Client) LogoURI() string {
	return c.config.LogoURI
}

func (c *Client) RedirectURI() string {
	return c.config.RedirectURI
}

type transportAddUserAgent struct {
	Transport http.RoundTripper
	UserAgent string
}

func (t *transportAddUserAgent) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.UserAgent)
	return t.Transport.RoundTrip(req)
}

func unmarshalTokenResponse(r io.Reader) (*oidc.TokenResponse, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	tokenResponse := new(oidc.TokenResponse)
	if err = json.Unmarshal(data, tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}

	return tokenResponse, nil
}
