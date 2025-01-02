package pep

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Guard interface {
	VerifyRequest(ctx *GuardContext, r *http.Request) error
}

type PEP struct {
	OAuth2ServerURI string
	RefreshInterval time.Duration
	Logger          *slog.Logger
	Jwks            jwk.Set
	HttpClient      *http.Client
	jwksMutex       sync.RWMutex
	stopChan        chan bool
}

type GuardContext struct {
	AccessTokenRaw   string
	AccessToken      jwt.Token
	SessionCookieRaw []byte
	ClaimsMap        map[string]interface{}
	Extra            map[string]interface{}
}

func New() *PEP {
	return &PEP{
		HttpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		RefreshInterval: 5 * time.Minute,
		Logger:          slog.Default(),
	}
}

const (
	ContextKeyAccessToken = "access_token"
	ContextKeyClaimsMap   = "claims_map"
)

type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

var ErrForbiddenHeadersInRequest = &Error{
	HttpStatus:  400,
	Code:        "forbidden_headers_in_request",
	Description: "Request contains forbidden headers",
}

var ErrNoAuthorizationHeader = &Error{
	HttpStatus:  400,
	Code:        "no_authorization_header",
	Description: "No Authorization header in request",
}

var ErrInvalidAuthorizationHeader = &Error{
	HttpStatus:  400,
	Code:        "invalid_authorization_header",
	Description: "Invalid Authorization header in request",
}

// Just enough elements to load the JWKS from the OAuth2 server
type AuthzServerMetadata struct {
	JwksURI string `json:"jwks_uri"`
}

// Reloads the JWKS from the OAuth2 server
func (p *PEP) ReloadJWKS() error {

	metadataURL := p.OAuth2ServerURI + "/.well-known/oauth-authorization-server"

	resp, err := p.HttpClient.Get(metadataURL)
	if err != nil {
		return fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	metadata := new(AuthzServerMetadata)
	err = json.NewDecoder(resp.Body).Decode(metadata)
	if err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}

	p.jwksMutex.Lock()
	defer p.jwksMutex.Unlock()

	p.Jwks, err = jwk.Fetch(context.Background(), metadata.JwksURI, jwk.WithHTTPClient(p.HttpClient))
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}

	return nil
}

// Start the periodic JWKS reload.
func (p *PEP) Start(ctx context.Context) error {
	p.Logger.Info("Starting PEP")
	p.stopChan = make(chan bool)
	interval := time.Duration(0)
	for {
		select {
		case <-p.stopChan:
			p.Logger.Info("stopped PEP")
			return nil
		case <-time.After(interval):
			err := p.ReloadJWKS()
			if err != nil {
				if interval == 0 {
					interval = 1 * time.Second
				} else {
					interval = interval * 2
					if interval > p.RefreshInterval {
						interval = p.RefreshInterval
					}
				}
				p.Logger.Error("Failed to load JWKS", "error", err, "retry_interval", interval)
			} else {
				p.Logger.Info("Loaded the JWKS")
				interval = p.RefreshInterval
			}
		}
	}

}

// Stop the periodic JWKS reload.
func (p *PEP) Stop() {
	if p.stopChan != nil {
		p.stopChan <- true
		close(p.stopChan)
		p.stopChan = nil
	}
}

// Check if request headers contains headers starting with "X-ZTA",
// which are forbidden in the request from the outside.
func (p *PEP) VerifyHeaders(c *GuardContext, r *http.Request) *Error {
	for k := range r.Header {
		n := strings.ToLower(k)
		if strings.HasPrefix(n, "x-zta") {
			return ErrForbiddenHeadersInRequest
		}
	}
	return nil
}

// Verify the self contained access token (JWT) using the previously loaded JWKS.
func (p *PEP) VerifyAccessToken(c *GuardContext, r *http.Request) *Error {
	authzHeaders := r.Header.Values("Authorization")
	if len(authzHeaders) == 0 {
		return ErrNoAuthorizationHeader
	}

	// we support bearer and dpop
	// we ignore other authz headers
	for _, authzHeader := range authzHeaders {
		parts := strings.Split(authzHeader, " ")
		if len(parts) != 2 {
			continue
		}

		tokenType := strings.ToLower(parts[0])
		if tokenType == "bearer" {
			claimsMap, err := p.VerifyJWTToken(parts[1])
			if err != nil {
				return err
			}
			c.AccessTokenRaw = parts[1]
			c.ClaimsMap = claimsMap
			return nil
		}
	}

	return ErrInvalidAuthorizationHeader
}

// Verify the JWT token using the previously loaded JWKS.
// Returns the claims map or an error.
func (p *PEP) VerifyJWTToken(token string) (map[string]interface{}, *Error) {
	t, err := jwt.ParseString(token, jwt.WithKeySet(p.Jwks, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, &Error{
			HttpStatus:  403,
			Code:        "invalid_token",
			Description: err.Error(),
		}
	}

	claims, err := t.AsMap(context.Background())
	if err != nil {
		return nil, &Error{
			HttpStatus:  403,
			Code:        "invalid_token",
			Description: err.Error(),
		}
	}

	return claims, nil
}

// Generate a random key of the given length in bits.
func GenerateRandomKey(bits int) ([]byte, error) {
	key := make([]byte, bits/8)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
