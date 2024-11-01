package epa

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gematik/zero-lab/go/vau"
)

const UserAgent = "zero-epa-client/0.1"

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

type Client struct {
	insecureSkipVerify bool
	certPool           *x509.CertPool
	httpClient         *http.Client
	channel            *vau.Channel
	urlAS              string
	urlASISA           string
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

func ResolveBaseURL(env Env, provider ProviderNumber) (string, string) {
	switch env {
	case EnvDev:
		return fmt.Sprintf("https://epa-as-%d.dev.epa4all.de", provider), fmt.Sprintf("epa-asisa-%d.dev.epa4all.de", provider)
	case EnvTest:
		return fmt.Sprintf("https://epa-as-%d.test.epa4all.de", provider), fmt.Sprintf("epa-asisa-%d.test.epa4all.de", provider)
	case EvnRef:
		return fmt.Sprintf("https://epa-as-%d.ref.epa4all.de", provider), fmt.Sprintf("epa-asisa-%d.ref.epa4all.de", provider)
	case EnvProd:
		return fmt.Sprintf("https://epa-as-%d.epa4all.de", provider), fmt.Sprintf("epa-asisa-%d.epa4all.de", provider)
	default:
		panic("unknown environment")
	}
}

func Connect(env Env, provider ProviderNumber, options ...ClientOption) (*Client, error) {

	client := &Client{}

	for _, option := range options {
		option(client)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: client.insecureSkipVerify,
			RootCAs:            client.certPool,
		},
	}
	// set User-Agent for all requests
	client.httpClient = &http.Client{
		Transport: &customTransport{
			t: transport,
		},
	}

	client.urlAS, client.urlASISA = ResolveBaseURL(env, provider)

	err := client.openVauChannel()
	if err != nil {
		return nil, err
	}

	return client, nil
}

type customTransport struct {
	t http.RoundTripper
}

func (c *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("user-agent", UserAgent)
	return c.t.RoundTrip(req)
}

func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}

func (c *Client) openVauChannel() error {
	vauChannel, err := vau.OpenChannel(c.urlAS, vau.EnvNonPU, c.httpClient)
	if err != nil {
		return err
	}
	c.channel = vauChannel
	return nil
}
