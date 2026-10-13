// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package vau_test

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/epa/vau"
)

type customTransport struct {
	t http.RoundTripper
}

func (c *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("x-useragent", "zero-lab-test/0.1.0")
	req.Header.Set("user-agent", "zero-lab-test/0.1.0")
	return c.t.RoundTrip(req)
}

func TestOpenChannel(t *testing.T) {
	baseURL := os.Getenv("EPA_VAU_BASE_URL")
	if baseURL == "" {
		t.Skip("EPA_VAU_BASE_URL not set — skipping live VAU OpenChannel test")
	}
	// do not check the server certificate
	httpClient := &http.Client{
		Transport: &customTransport{
			t: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Disable certificate verification
				},
			},
		},
	}
	channel, err := vau.OpenChannel(baseURL, vau.EnvNonPU, httpClient)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	t.Logf("Channel: %v", channel)

	req, err := http.NewRequest("GET", "/epa/authz/v1/getNonce", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("x-useragent", "CLIENTID1234567890AB/2.1.12-45")

	resp, err := channel.Do(req)
	if err != nil {
		log.Fatalf("sending request to EPA: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response: %s", body)
}

func TestMockOpenChannel(t *testing.T) {
	server, err := vau.NewServer()
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	mockServer := httptest.NewServer(server)
	defer mockServer.Close()
	baseURL := mockServer.URL

	httpClient := &http.Client{}
	channel, err := vau.OpenChannel(baseURL, vau.EnvNonPU, httpClient)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	t.Logf("Channel: %v", channel)

	req, err := http.NewRequest("GET", "/epa/authz/v1/getNonce", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("x-useragent", "CLIENTID1234567890AB/2.1.12-45")

	resp, err := channel.Do(req)
	if err != nil {
		log.Fatalf("sending request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response: %s", body)
}
