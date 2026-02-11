package kon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
)

type ConnectorContext struct {
	MandantId      string
	ClientSystemId string
	WorkplaceId    string
	UserId         string
}

type Client struct {
	httpClient *http.Client
	BaseURL    *url.URL
	Context    ConnectorContext
	Services   *ConnectorServices
	Config     *ClientConfig
}

// NewHTTPClient creates an http.Client and base URL from a Dotkon config.
// It configures TLS and credentials but does not contact the Konnektor.
func NewHTTPClient(config *Dotkon) (*http.Client, *url.URL, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         config.ExpectedHost,
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
	}

	if len(config.TrustedCertificates) > 0 {
		certPool := x509.NewCertPool()
		for _, cert := range config.TrustedCertificates {
			slog.Debug("adding trusted certificate", "subject", cert.Subject)
			certPool.AddCert(cert)
		}
		transport.TLSClientConfig.RootCAs = certPool
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	if config.Credentials != nil {
		switch cred := config.Credentials.(type) {
		case CredentialsConfigBasic:
			httpClient.Transport = &basicAuthTransport{
				username: cred.Username,
				password: cred.Password,
				T:        transport,
			}
		case CredentialsConfigPKCS12:
			cert, err := parsePKCS12Credential(cred)
			if err != nil {
				return nil, nil, fmt.Errorf("parsing PKCS#12 credentials: %w", err)
			}
			transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		default:
			return nil, nil, fmt.Errorf("unsupported credentials type")
		}
	}

	baseURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing base URL: %w", err)
	}

	return httpClient, baseURL, nil
}

func NewClient(dotkon *Dotkon, opts ...ClientOption) (*Client, error) {
	config := defaultClientConfig()
	for _, opt := range opts {
		opt(config)
	}

	httpClient, baseURL, err := NewHTTPClient(dotkon)
	if err != nil {
		return nil, err
	}

	client := &Client{
		httpClient: httpClient,
		BaseURL:    baseURL,
		Context: ConnectorContext{
			MandantId:      dotkon.MandantId,
			ClientSystemId: dotkon.ClientSystemId,
			WorkplaceId:    dotkon.WorkplaceId,
			UserId:         dotkon.UserId,
		},
		Config: config,
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.ShortTimeout)
	defer cancel()

	client.Services, err = LoadConnectorServices(ctx, client.httpClient, client.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("loading connector services: %w", err)
	}

	if dotkon.RewriteServiceEndpoints {
		client.Services.RewriteEndpoints(baseURL)
	}

	return client, nil
}

type basicAuthTransport struct {
	username string
	password string
	T        http.RoundTripper
}

func (t *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.SetBasicAuth(t.username, t.password)
	return t.T.RoundTrip(req)
}

func (c *Client) CreateServiceProxy(serviceName ServiceName, version string) (*serviceProxy, error) {
	var service *Service
	var serviceVersion *ServiceVersion

	for _, s := range c.Services.ServiceInformation.Service {
		if s.Name == serviceName {
			for _, v := range s.Versions {
				if v.Version == version {
					service = &s
					serviceVersion = &v
					break
				}
			}
		}
	}
	if serviceVersion == nil {
		return nil, fmt.Errorf("service version not found: %s %s", serviceName, version)
	}
	slog.Debug("creating service proxy", "service", serviceName, "version", version, "endpointTLS", serviceVersion.EndpointTLS.Location)
	return &serviceProxy{
		endpoint:       serviceVersion.EndpointTLS.Location,
		client:         c,
		service:        service,
		serviceVersion: serviceVersion,
	}, nil
}

func parsePKCS12Credential(cred CredentialsConfigPKCS12) (tls.Certificate, error) {
	data, err := base64.StdEncoding.DecodeString(cred.Data)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decoding base64 PKCS#12 data: %w", err)
	}
	return parsePKCS12Data(data, cred.Password)
}

func parsePKCS12Data(data []byte, password string) (tls.Certificate, error) {
	if legacy.IsBER(data) {
		converted, err := legacy.ConvertWithOpenSSL(data, password)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("converting legacy BER-encoded PKCS#12: %w", err)
		}
		data = converted
	}

	bags, err := pkcs12.Decode(data, []byte(password))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decoding PKCS#12 container: %w", err)
	}

	pairs := bags.FindMatchingPairs()
	if len(pairs) == 0 {
		return tls.Certificate{}, fmt.Errorf("PKCS#12 container has no matching certificate/key pairs")
	}

	pair := pairs[0]
	leaf, err := x509.ParseCertificate(pair.Certificate.Raw)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing certificate from PKCS#12: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing private key from PKCS#12: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// converts a sem version string to a number for sorting and comparing
// errors are ignored, if the version string is not a valid semver string, 0 is returned
func semverAsNumber(version string) int {
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	matches := re.FindStringSubmatch(version)
	if len(matches) != 4 {
		return 0
	}

	toInt := func(s string) int {
		i, _ := strconv.Atoi(s)
		return i
	}

	major := 10000 * toInt(matches[1])
	minor := 100 * toInt(matches[2])
	patch := toInt(matches[3])

	return major + minor + patch
}
