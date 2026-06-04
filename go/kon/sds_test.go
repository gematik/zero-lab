package kon

import (
	"log/slog"
	"net/url"
	"testing"
)

func init() {
	// set slog level to debug
	slog.SetLogLoggerLevel(slog.LevelDebug)
}

func TestLoadConnectorServices(t *testing.T) {
	server := newTestSDSServer(t)

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse mock URL: %v", err)
	}

	got, err := LoadConnectorServices(t.Context(), server.Client(), u)
	if err != nil {
		t.Fatalf("LoadConnectorServices: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil ConnectorServices")
	}
}
