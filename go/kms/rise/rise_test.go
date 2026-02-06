package rise_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/kms/rise"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/login":
			w.WriteHeader(http.StatusOK)
		case "/info":
			infomodel := &rise.Infomodell{
				Mandant:      "Mandant-1",
				Clientsystem: "Clientsystem-1",
				Workplace:    "Workplace-1",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(infomodel); err != nil {
				t.Fatalf("Error encoding infomodel: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Test rise
	r := rise.New(rise.WithURL(server.URL), rise.WithHTTPClient(server.Client()))
	assert.NotNil(t, r)
	err := r.Login(server.URL, "user", "password")
	assert.NoError(t, err)
	var infomodel *rise.Infomodell
	infomodel, err = r.GetInfomodel()
	assert.NoError(t, err)
	assert.NotNil(t, infomodel)
	assert.Equal(t, "Mandant-1", infomodel.Mandant)
}
