package epa

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/vau"
)

const UserAgent = "zero-epa-client/0.1"

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

func WithTokenSignFunc(tokenSignFunc brainpool.SignFunc) ClientOption {
	return func(s *Session) {
		s.tokenSignFunc = tokenSignFunc
	}
}

type Session struct {
	insecureSkipVerify bool
	certPool           *x509.CertPool
	HttpClient         *http.Client
	VAUChannel         *vau.Channel
	baseURL            string
	tokenSignFunc      brainpool.SignFunc
	// TODO: make better
	AttestCertificate *x509.Certificate
	// TODO: make better
	ProofOfAuditEvidenceFunc ProofOfAuditEvidenceFunc
}

// enumeration for environment
type Env string

const (
	EnvDev  Env = "dev"
	EnvTest Env = "test"
	EvnRef  Env = "ref"
	EnvProd Env = "prod"
)

type ProviderNumber int

const (
	ProviderNumber1 ProviderNumber = 1
	ProviderNumber2 ProviderNumber = 2
)

func ResolveBaseURL(env Env, provider ProviderNumber) string {
	switch env {
	case EnvDev:
		return fmt.Sprintf("https://epa-as-%d.dev.epa4all.de", provider)
	case EnvTest:
		return fmt.Sprintf("https://epa-as-%d.test.epa4all.de", provider)
	case EvnRef:
		return fmt.Sprintf("https://epa-as-%d.ref.epa4all.de", provider)
	case EnvProd:
		return fmt.Sprintf("https://epa-as-%d.epa4all.de", provider)
	default:
		panic("unknown environment")
	}
}

func OpenSession(env Env, provider ProviderNumber, options ...ClientOption) (*Session, error) {

	session := &Session{}

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
		Timeout: 10 * time.Second,
	}

	session.baseURL = ResolveBaseURL(env, provider)

	err := session.openVauChannel()
	if err != nil {
		return nil, err
	}

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
	vauChannel, err := vau.OpenChannel(s.baseURL, vau.EnvNonPU, s.HttpClient)
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
	typedError := new(ErrorType)
	if err := json.NewDecoder(bodyData).Decode(typedError); err != nil {
		return fmt.Errorf(fmt.Sprintf("http status %d: %s", resp.StatusCode, bodyData.String()))
	}
	typedError.HttpStatusCode = resp.StatusCode
	return typedError
}
