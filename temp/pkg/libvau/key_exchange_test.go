package libvau_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/pkg/libvau"
)

func TestOpenChannel(t *testing.T) {
	baseURL := "http://localhost:8081"
	httpClient := &http.Client{}
	channel, err := libvau.OpenChannel(baseURL, libvau.EnvNonPU, httpClient)
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
	server, err := libvau.NewServer()
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	mockServer := httptest.NewServer(server)
	defer mockServer.Close()
	baseURL := mockServer.URL

	httpClient := &http.Client{}
	channel, err := libvau.OpenChannel(baseURL, libvau.EnvNonPU, httpClient)
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
