package authzserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Registration is closed: any request gets a coherent 403 access_denied, not a 404 or a 501 placeholder.
func TestRegistrationEndpointClosed(t *testing.T) {
	server, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, testIssuer+"/registration",
		strings.NewReader(`{"redirect_uris":["https://rp.example.com/cb"]}`))
	req.Header.Set("Content-Type", "application/json")

	err := server.RegistrationEndpoint(rec, req)
	authzErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if authzErr.HttpStatus != http.StatusForbidden {
		t.Errorf("status = %d, want 403", authzErr.HttpStatus)
	}
	if authzErr.Code != "access_denied" {
		t.Errorf("error code = %q, want access_denied (%s)", authzErr.Code, authzErr.Description)
	}
}

// The endpoint stays advertised even while closed, so discovery metadata is stable.
func TestRegistrationEndpointStillAdvertised(t *testing.T) {
	server, _ := newTestServer(t)
	if server.Metadata.RegistrationEndpoint == "" {
		t.Error("registration_endpoint should remain advertised in the metadata")
	}
}
