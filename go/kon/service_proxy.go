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
