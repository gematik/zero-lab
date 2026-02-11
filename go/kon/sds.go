package kon

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

type LocalProductVersion struct {
	HWVersion string `xml:"HWVersion" json:"hwVersion"`
	FWVersion string `xml:"FWVersion" json:"fwVersion"`
}

type ProductVersion struct {
	Local LocalProductVersion `xml:"Local" json:"local"`
}

type ProductIdentification struct {
	ProductVendorID string         `xml:"ProductVendorID" json:"productVendorId"`
	ProductCode     string         `xml:"ProductCode" json:"productCode"`
	ProductVersion  ProductVersion `xml:"ProductVersion" json:"productVersion"`
}

type ProductTypeInformation struct {
	ProductType        string `xml:"ProductType" json:"productType"`
	ProductTypeVersion string `xml:"ProductTypeVersion" json:"productTypeVersion"`
}

type ProductInformation struct {
	ProductTypeInformation ProductTypeInformation `xml:"ProductTypeInformation" json:"productTypeInformation"`
	ProductIdentification  ProductIdentification  `xml:"ProductIdentification" json:"productIdentification"`
}

type ServiceVersionEndpoint struct {
	Location string `xml:"Location,attr" json:"location"`
}

type ServiceVersion struct {
	TargetNamespace string                  `xml:"TargetNamespace,attr" json:"targetNamespace"`
	Version         string                  `xml:"Version,attr" json:"version"`
	Abstract        string                  `xml:"Abstract" json:"abstract"`
	EndpointTLS     *ServiceVersionEndpoint `xml:"EndpointTLS,omitempty" json:"endpointTLS,omitempty"`
	Endpoint        *ServiceVersionEndpoint `xml:"Endpoint,omitempty" json:"endpoint,omitempty"`
}

type ServiceName string

const (
	ServiceNameCardService          ServiceName = "CardService"
	ServiceNameEventService         ServiceName = "EventService"
	ServiceNameAuthSignatureService ServiceName = "AuthSignatureService"
	ServiceNameCartTerminalService  ServiceName = "CardTerminalService"
	ServiceNameCertificateService   ServiceName = "CertificateService"
)

type Service struct {
	XMLName  xml.Name         `xml:"Service" json:"-"`
	Name     ServiceName      `xml:"Name,attr" json:"name"`
	Abstract string           `xml:"Abstract" json:"abstract"`
	Versions []ServiceVersion `xml:"Versions>Version" json:"versions"`
}

type ServiceInformation struct {
	Service []Service `xml:"Service" json:"services"`
}

type ConnectorServices struct {
	Raw                []byte             `json:"-"`
	ProductInformation ProductInformation `json:"productInformation"`
	ServiceInformation ServiceInformation `json:"serviceInformation"`
}

// RewriteEndpoints replaces the scheme and host of all EndpointTLS locations
// with the scheme and host from baseURL, preserving the original path.
func (cs *ConnectorServices) RewriteEndpoints(baseURL *url.URL) {
	for i := range cs.ServiceInformation.Service {
		for j := range cs.ServiceInformation.Service[i].Versions {
			v := &cs.ServiceInformation.Service[i].Versions[j]
			if v.EndpointTLS != nil && v.EndpointTLS.Location != "" {
				v.EndpointTLS.Location = rewriteLocation(v.EndpointTLS.Location, baseURL)
			}
			if v.Endpoint != nil && v.Endpoint.Location != "" {
				v.Endpoint.Location = rewriteLocation(v.Endpoint.Location, baseURL)
			}
		}
	}
}

func rewriteLocation(location string, baseURL *url.URL) string {
	parsed, err := url.Parse(location)
	if err != nil {
		return location
	}
	parsed.Scheme = baseURL.Scheme
	parsed.Host = baseURL.Host
	return parsed.String()
}

func LoadConnectorServices(ctx context.Context, httpClient *http.Client, baseUrl *url.URL) (*ConnectorServices, error) {
	services := new(ConnectorServices)
	url := baseUrl.ResolveReference(&url.URL{Path: "./connector.sds"})

	slog.Debug("Loading service directory", "url", url.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating SDS request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading service directory response: %w", err)
	}
	services.Raw = raw

	if err := xml.NewDecoder(bytes.NewReader(raw)).Decode(services); err != nil {
		return nil, err
	}

	slog.Debug("Loaded service directory", "services", services)

	for _, s := range services.ServiceInformation.Service {
		slog.Debug("Service", "name", s.Name, "versionsCount", len(s.Versions))
		for _, v := range s.Versions {
			slog.Debug("Version", "version", v)
		}
	}

	return services, nil
}
