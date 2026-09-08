package kon

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"time"
)

type serviceProxy struct {
	endpoint       string
	client         *Client
	service        *Service
	serviceVersion *ServiceVersion
}

func (s *serviceProxy) String() string {
	return fmt.Sprintf("%s version=%s endpoint=%s", s.service.Name, s.serviceVersion.Version, s.endpoint)
}

func (s *serviceProxy) CreateSOAPRequest(ctx context.Context, op SOAPOperation, envelope any) (*http.Request, error) {
	body, err := xml.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshaling SOAP envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating SOAP request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", op.SOAPAction())
	return req, nil
}

// Call executes a SOAP operation using the given context for cancellation and deadlines.
func (s *serviceProxy) Call(ctx context.Context, op SOAPOperation, envelope any, response any) error {
	if s.endpoint == "" {
		return fmt.Errorf("service %s version %s has no endpoint", s.service.Name, s.serviceVersion.Version)
	}

	req, err := s.CreateSOAPRequest(ctx, op, envelope)
	if err != nil {
		return err
	}

	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		dump, _ := httputil.DumpRequestOut(req, true)
		slog.Debug("SOAP request\n" + string(dump))
	}
	start := time.Now()

	resp, err := s.client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("performing SOAP request: %w", err)
	}
	defer resp.Body.Close()

	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading SOAP response: %w", err)
	}

	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		dump, _ := httputil.DumpResponse(resp, false)
		slog.Debug(fmt.Sprintf("SOAP response (%s)\n%s%s", time.Since(start), dump, body))
	}

	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(response); err != nil {
		return fmt.Errorf("decoding SOAP response: %w", err)
	}

	return nil
}

// createServiceProxy returns a proxy for the newest version of serviceName the
// Konnektor advertises whose major.minor is one of supportedVersions, which the
// caller lists according to the bindings it can actually marshal.
//
// Konnektors advertise versions we have no bindings for — the RISE connector
// lists CardService 8.2.1 ahead of the 8.1.x versions — and each minor version
// has its own XML namespace, so posting a v8.1 body to the v8.2 endpoint is
// answered with a SOAP syntax fault. The binding, not the connector, therefore
// decides which advertised version we talk to.
func (c *Client) createServiceProxy(serviceName ServiceName, supportedVersions ...string) (*serviceProxy, error) {
	var bestService *Service
	var bestVersion *ServiceVersion
	var bestSemver int
	var advertised []string

	for i, s := range c.Services.ServiceInformation.Service {
		if s.Name != serviceName {
			continue
		}
		for j, v := range s.Versions {
			advertised = append(advertised, v.Version)
			if !slices.Contains(supportedVersions, majorMinor(v.Version)) {
				continue
			}
			if sv := semverAsNumber(v.Version); sv > bestSemver {
				bestService = &c.Services.ServiceInformation.Service[i]
				bestVersion = &c.Services.ServiceInformation.Service[i].Versions[j]
				bestSemver = sv
			}
		}
	}

	if bestVersion == nil {
		if len(advertised) == 0 {
			return nil, fmt.Errorf("service not found: %s", serviceName)
		}
		return nil, fmt.Errorf("%s: connector advertises %s, none supported (supported: %s)",
			serviceName, strings.Join(advertised, ", "), strings.Join(supportedVersions, ", "))
	}

	var endpoint string
	switch {
	case bestVersion.EndpointTLS != nil:
		endpoint = bestVersion.EndpointTLS.Location
	case bestVersion.Endpoint != nil:
		endpoint = bestVersion.Endpoint.Location
	}

	slog.Debug("Selected service version", "service", serviceName, "version", bestVersion.Version, "endpoint", endpoint)

	return &serviceProxy{
		endpoint:       endpoint,
		client:         c,
		service:        bestService,
		serviceVersion: bestVersion,
	}, nil
}

// majorMinor reduces a service version like "8.2.1" to the "8.2" that identifies
// its XML namespace and thus the generated binding to use.
func majorMinor(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}
