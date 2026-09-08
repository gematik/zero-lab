package kon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testCardServiceSDS = `<?xml version="1.0" encoding="UTF-8"?>
<ConnectorSDS xmlns="http://ws.gematik.de/conn/ServiceDirectory/v3.1">
  <ServiceInformation>
    <Service Name="CardService">
      <Abstract>CardService</Abstract>
      <Versions>
%%VERSIONS%%
      </Versions>
    </Service>
  </ServiceInformation>
</ConnectorSDS>`

const cardServiceVersion81 = `
        <Version TargetNamespace="http://ws.gematik.de/conn/CardService/v8.1" Version="8.1.2">
          <Abstract>CardService v8.1.2</Abstract>
          <EndpointTLS Location="%%ENDPOINT%%/ws/CardService81"/>
        </Version>`

const cardServiceVersion82 = `
        <Version TargetNamespace="http://ws.gematik.de/conn/CardService/v8.2" Version="8.2.1">
          <Abstract>CardService v8.2.1</Abstract>
          <EndpointTLS Location="%%ENDPOINT%%/ws/CardService82"/>
        </Version>`

const testVerifyPinResponse = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns:VerifyPinResponse xmlns:ns="%%NS%%"
                          xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0"
                          xmlns:ns5="http://ws.gematik.de/conn/CardServiceCommon/v2.0">
      <ns2:Status>
        <Result>OK</Result>
      </ns2:Status>
      <ns5:PinResult>OK</ns5:PinResult>
    </ns:VerifyPinResponse>
  </soap:Body>
</soap:Envelope>`

// newTestCardServiceKonnektor serves an SDS advertising the given CardService
// versions, with each version's endpoint recording the request it received.
func newTestCardServiceKonnektor(t *testing.T, versions ...string) (*Client, map[string]string) {
	t.Helper()

	requests := make(map[string]string)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		switch r.URL.Path {
		case "/connector.sds":
			sds := strings.ReplaceAll(testCardServiceSDS, "%%VERSIONS%%", strings.Join(versions, "\n"))
			_, _ = w.Write([]byte(strings.ReplaceAll(sds, "%%ENDPOINT%%", server.URL)))
		case "/ws/CardService81", "/ws/CardService82":
			body, _ := io.ReadAll(r.Body)
			requests[r.URL.Path] = string(body)
			ns := "http://ws.gematik.de/conn/CardService/v8.1"
			if r.URL.Path == "/ws/CardService82" {
				ns = "http://ws.gematik.de/conn/CardService/v8.2"
			}
			_, _ = w.Write([]byte(strings.ReplaceAll(testVerifyPinResponse, "%%NS%%", ns)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(&Dotkon{URL: server.URL, MandantId: "M1", ClientSystemId: "C1", WorkplaceId: "W1"})
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	return client, requests
}

// A Konnektor advertising CardService 8.2.1 alongside 8.1.x (as the RISE
// connector does) must still be addressed on its v8.1 endpoint: that is the
// namespace our bindings marshal.
func TestVerifyPinPicksSupportedVersion(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
	}{
		{"8.1 only", []string{cardServiceVersion81}},
		{"8.2 advertised first", []string{cardServiceVersion82, cardServiceVersion81}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, requests := newTestCardServiceKonnektor(t, tt.versions...)

			resp, err := client.VerifyPin(context.Background(), "card-1", PinTypSMC)
			if err != nil {
				t.Fatalf("VerifyPin: %v", err)
			}
			if resp.PinResult != "OK" {
				t.Errorf("PinResult = %s, want OK", resp.PinResult)
			}

			if _, ok := requests["/ws/CardService82"]; ok {
				t.Error("request went to the v8.2 endpoint")
			}
			body, ok := requests["/ws/CardService81"]
			if !ok {
				t.Fatalf("no request to /ws/CardService81, got requests to %v", keys(requests))
			}
			if !strings.Contains(body, "http://ws.gematik.de/conn/CardService/v8.1") {
				t.Errorf("request body does not use the v8.1 namespace:\n%s", body)
			}
		})
	}
}

// A connector offering only versions we have no binding for must fail with a
// diagnosable error rather than being addressed with a mismatched namespace.
func TestVerifyPinUnsupportedVersion(t *testing.T) {
	client, requests := newTestCardServiceKonnektor(t, cardServiceVersion82)

	_, err := client.VerifyPin(context.Background(), "card-1", PinTypSMC)
	if err == nil {
		t.Fatal("expected error for unsupported CardService version")
	}
	if !strings.Contains(err.Error(), "8.2.1") {
		t.Errorf("error should name the advertised version, got: %v", err)
	}
	if len(requests) != 0 {
		t.Errorf("no SOAP request expected, got %v", keys(requests))
	}
}

func TestCreateServiceProxyMissingEndpoint(t *testing.T) {
	const noEndpoint = `
        <Version TargetNamespace="http://ws.gematik.de/conn/CardService/v8.1" Version="8.1.2">
          <Abstract>CardService v8.1.2</Abstract>
        </Version>`

	client, _ := newTestCardServiceKonnektor(t, noEndpoint)

	proxy, err := client.createServiceProxy(ServiceNameCardService, "8.1")
	if err != nil {
		t.Fatalf("createServiceProxy: %v", err)
	}
	if proxy.endpoint != "" {
		t.Errorf("endpoint = %q, want empty", proxy.endpoint)
	}
	if err := proxy.Call(context.Background(), &noopOperation{}, struct{}{}, &struct{}{}); err == nil {
		t.Error("expected error calling a version without an endpoint")
	}
}

type noopOperation struct{}

func (noopOperation) Name() string        { return "Noop" }
func (noopOperation) SOAPAction() string  { return "" }
func (noopOperation) BindingType() string { return "" }

func keys(m map[string]string) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, fmt.Sprintf("%q", k))
	}
	return s
}
