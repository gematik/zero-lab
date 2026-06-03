package epa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa/vau"
)

var UserAgent = fmt.Sprintf("zero-epa-client/%s", Version)

type ClientOption func(*Client)

func WithInsecureSkipVerify() ClientOption {
	return func(c *Client) {
		c.insecureSkipVerify = true
	}
}

func WithCertPool(certPool *x509.CertPool) ClientOption {
	return func(c *Client) {
		c.certPool = certPool
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.Timeout = timeout
	}
}

type SecurityFunctions struct {
	AuthnSignFunc           brainpool.SignFunc
	AuthnCertFunc           func() (*x509.Certificate, error)
	ClientAssertionSignFunc brainpool.SignFunc
	ClientAssertionCertFunc func() (*x509.Certificate, error)
	ProvidePN               ProvidePNFunc
	ProvideHCV              func(insurantId string) ([]byte, error)
}

// Client is a cheap, pre-VAU handle to an aggregator. It owns the HTTP
// transport and identity material needed for both the unauthenticated
// /information endpoints and for opening a VAU session.
//
// Methods that hit /information endpoints (e.g. GetRecordStatus,
// GetConsentDecisionInformation) live on *Client and do NOT require an open
// VAU channel. Use OpenSession to upgrade to a *Session for VAU-bound calls.
type Client struct {
	Env                Env
	ProviderNumber     ProviderNumber
	BaseURL            string
	HttpClient         *http.Client
	securityFunctions  *SecurityFunctions
	insecureSkipVerify bool
	certPool           *x509.CertPool
	Timeout            time.Duration
}

// Session is a Client with an open VAU channel. Authorize must be called
// before VAU-bound operations like Entitle.
type Session struct {
	*Client
	VAUChannel *vau.Channel
	OpenedAt   time.Time
}

// enumeration for environment
type Env string

const (
	EnvDev  Env = "dev"
	EnvTest Env = "test"
	EnvRef  Env = "ref"
	EnvProd Env = "prod"
)

func (e Env) String() string {
	return string(e)
}

func EnvFromString(s string) (Env, error) {
	switch s {
	case "dev":
		return EnvDev, nil
	case "test":
		return EnvTest, nil
	case "ref":
		return EnvRef, nil
	case "prod":
		return EnvProd, nil
	default:
		return "", fmt.Errorf("unknown environment: %s", s)
	}
}

type ProviderNumber int

const (
	ProviderNumber1 ProviderNumber = 1
	ProviderNumber2 ProviderNumber = 2
	ProviderNumber3 ProviderNumber = 3
)

var AllProviders = []ProviderNumber{ProviderNumber1, ProviderNumber2, ProviderNumber3}

func ResolveBaseURL(env Env, provider ProviderNumber) string {
	switch env {
	case EnvDev:
		return fmt.Sprintf("https://epa-as-%d.dev.epa4all.de", provider)
	case EnvTest:
		return fmt.Sprintf("https://epa-as-%d.test.epa4all.de", provider)
	case EnvRef:
		return fmt.Sprintf("https://epa-as-%d.ref.epa4all.de", provider)
	case EnvProd:
		return fmt.Sprintf("https://epa-as-%d.epa4all.de", provider)
	default:
		panic("unknown environment")
	}
}

// NewClient builds a Client for the given aggregator. It does not perform
// any network calls; the returned Client is ready to use for /information
// endpoints, and may be promoted to a *Session via OpenSession when a VAU
// channel is needed.
func NewClient(env Env, provider ProviderNumber, sf *SecurityFunctions, options ...ClientOption) (*Client, error) {
	client := &Client{
		Env:               env,
		ProviderNumber:    provider,
		securityFunctions: sf,
	}

	for _, option := range options {
		option(client)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: client.insecureSkipVerify,
			RootCAs:            client.certPool,
		},
	}

	client.HttpClient = &http.Client{
		Transport: &customTransport{
			t: transport,
		},
	}

	if client.Timeout > 0 {
		client.HttpClient.Timeout = client.Timeout
	} else {
		client.HttpClient.Timeout = 5 * time.Second
	}

	client.BaseURL = ResolveBaseURL(env, provider)

	return client, nil
}

// OpenSession performs the VAU handshake and returns a Session that can be
// Authorized for VAU-bound calls. The underlying Client (HTTP transport,
// identity) is shared with the returned Session via embedding.
func (c *Client) OpenSession() (*Session, error) {
	vauChannel, err := vau.OpenChannel(c.BaseURL, vau.EnvNonPU, c.HttpClient)
	if err != nil {
		return nil, err
	}

	return &Session{
		Client:     c,
		VAUChannel: vauChannel,
		OpenedAt:   time.Now(),
	}, nil
}

type customTransport struct {
	t http.RoundTripper
}

func (c *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("user-agent", UserAgent)
	return c.t.RoundTrip(req)
}

// Close releases idle HTTP connections held by the Client.
func (c *Client) Close() {
	c.HttpClient.CloseIdleConnections()
}

type ErrorType struct {
	HttpStatusCode int    `json:"-"`
	ErrorCode      string `json:"errorCode"`
	ErrorDetail    string `json:"errorDetail,omitempty"`
}

func (e *ErrorType) Error() string {
	return fmt.Sprintf("http error: %d, error code: %s, error detail: %s", e.HttpStatusCode, e.ErrorCode, e.ErrorDetail)
}

func parseHttpError(resp *http.Response) error {
	defer resp.Body.Close()
	bodyData := new(bytes.Buffer)
	if _, err := bodyData.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	bodyStr := bodyData.String()

	if bodyStr == "" {
		bodyStr = http.StatusText(resp.StatusCode)
	}

	typedError := new(ErrorType)
	if err := json.NewDecoder(bodyData).Decode(typedError); err != nil {
		return fmt.Errorf("http status %d: %s", resp.StatusCode, bodyStr)
	}
	typedError.HttpStatusCode = resp.StatusCode
	return typedError
}

func (s *Session) HealthCheck() error {
	_, err := s.GetStatus()
	if err == nil {
		return nil
	} else {
		slog.Error("Health check failed", "error", err, "opened_at", s.OpenedAt, "base_url", s.BaseURL)
		return err
	}
}

func (s *Session) GetStatus() (*vau.Status, error) {
	req, err := http.NewRequest("GET", "/VAU-Status", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("x-useragent", UserAgent)

	resp, err := s.VAUChannel.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d. error: %s", resp.StatusCode, string(body))
	}

	status := new(vau.Status)
	if err := json.NewDecoder(resp.Body).Decode(status); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	return status, nil
}
