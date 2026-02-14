package kon_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/kon"
)

func TestClientWithSelfSignedCert(t *testing.T) {
	// Start a local HTTPS server wrapped in httptest
	// httptest automatically generates a self-signed certificate
	// and serves over HTTPS when NewTLSServer is used.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from self-signed server"))
	}))
	defer server.Close()

	// External libraries or clients (like kon.Client) need to trust this
	// self-signed certificate. We extract it from the server.
	cert := server.TLS.Certificates[0].Certificate[0]
	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("Failed to parse server certificate: %v", err)
	}

	// Configure the Dotkon helper. We explicitly add the server's
	// certificate to the TrustedCertificates list.
	config := &kon.Dotkon{
		URL:                 server.URL,
		TrustedCertificates: []*x509.Certificate{parsedCert},
		// ExpectedHost is not set, so the client will verify the hostname
		// against the certificate. httptest certs cover 127.0.0.1,
		// so it matches server.URL.
	}

	// Create the HTTP client using the configuration
	client, _, err := kon.NewHTTPClient(config)
	if err != nil {
		t.Fatalf("Failed to create HTTP client: %v", err)
	}

	// Make a request to the server to verify the TLS handshake works
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}
}

func TestServerCertificate(t *testing.T) {
	// Start a local HTTPS server wrapped in httptest
	// httptest automatically generates a self-signed certificate
	// and serves over HTTPS when NewTLSServer is used.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from self-signed server"))
	}))
	defer server.Close()

	tlsCert, err := kon.LoadServerCertificate(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("error loading server certificate: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(tlsCert)

	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            certPool,
		ServerName:         tlsCert.DNSNames[0],
	}

	transport := &http.Transport{TLSClientConfig: config}

	httpClient := http.Client{Transport: transport}

	resp, err := httpClient.Get(server.URL)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}

	// negative test - without adding the server certificate to the pool, the request should fail
	transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}
	httpClient = http.Client{Transport: transport}

	_, err = httpClient.Get(server.URL)
	if err == nil {
		t.Fatal("Expected TLS handshake error, got none")
	}

}
