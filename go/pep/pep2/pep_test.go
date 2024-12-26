package pep2_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pep "github.com/gematik/zero-lab/go/pep/pep2"
)

func TestPEPBuilder(t *testing.T) {
	pep, err := pep.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("PEP: %v", pep)
}

func TestPEPGuard(t *testing.T) {

	p, _ := pep.NewBuilder().
		Build()

	denyAllGuard, err := p.NewGuard().
		DenyAll().
		Build()

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Guard: %v", denyAllGuard)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /public", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public"))
	})

	mux.HandleFunc("GET /private",
		p.GuardedHandlerFunc(denyAllGuard, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("private"))
		}),
	)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()

	tests := []struct {
		url            string
		expectedStatus int
		expectedBody   string
	}{
		{url: "/public", expectedStatus: http.StatusOK, expectedBody: "public"},
		{url: "/private", expectedStatus: http.StatusForbidden, expectedBody: "private"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			resp, err := client.Get(server.URL + tt.url)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, string(body))
			}
		})
	}

}
