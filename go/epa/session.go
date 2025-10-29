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
	"github.com/gematik/zero-lab/go/vau"
)

var UserAgent = fmt.Sprintf("zero-epa-client/%s", Version)

type ClientOption func(*Session)

func WithInsecureSkipVerify() ClientOption {
	return func(s *Session) {
		s.insecureSkipVerify = true
	}
}

func WithCertPool(certPool *x509.CertPool) ClientOption {
	return func(s *Session) {
		s.certPool = certPool
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(s *Session) {
		s.Timeout = timeout
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

type Session struct {
	Env                Env
	ProviderNumber     ProviderNumber
	BaseURL            string
	OpenedAt           time.Time
	securityFunctions  *SecurityFunctions
	insecureSkipVerify bool
	certPool           *x509.CertPool
	HttpClient         *http.Client
	VAUChannel         *vau.Channel
	Timeout            time.Duration
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
)

var AllProviders = []ProviderNumber{ProviderNumber1, ProviderNumber2}

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

func OpenSession(env Env, provider ProviderNumber, sf *SecurityFunctions, options ...ClientOption) (*Session, error) {

	session := &Session{
		Env:               env,
		ProviderNumber:    provider,
		securityFunctions: sf,
	}

	for _, option := range options {
		option(session)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: session.insecureSkipVerify,
			RootCAs:            session.certPool,
		},
	}

	// set User-Agent for all requests
	session.HttpClient = &http.Client{
		Transport: &customTransport{
			t: transport,
		},
	}

	if session.Timeout > 0 {
		session.HttpClient.Timeout = session.Timeout
	} else {
		// default timeout 5 seconds
		session.HttpClient.Timeout = 5 * time.Second
	}

	session.BaseURL = ResolveBaseURL(env, provider)

	err := session.openVauChannel()
	if err != nil {
		return nil, err
	}

	session.OpenedAt = time.Now()

	return session, nil
}

type customTransport struct {
	t http.RoundTripper
}

func (c *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("user-agent", UserAgent)
	return c.t.RoundTrip(req)
}

func (s *Session) Close() {
	s.HttpClient.CloseIdleConnections()
}

func (s *Session) openVauChannel() error {
	vauChannel, err := vau.OpenChannel(s.BaseURL, vau.EnvNonPU, s.HttpClient)
	if err != nil {
		return err
	}
	s.VAUChannel = vauChannel
	return nil
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
