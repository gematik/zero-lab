package asl_test

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/asl"
)

func TestMockOpenChannel(t *testing.T) {
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(logHandler))
	server, err := asl.NewServer()
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	mockServer := httptest.NewServer(server)
	defer mockServer.Close()
	baseURL := mockServer.URL

	httpClient := &http.Client{}
	channel, err := asl.OpenChannel(baseURL, asl.EnvNonPU, asl.ProfileZetaAsl, httpClient)
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
