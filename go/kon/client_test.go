package kon_test

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/kon"
)

func TestServerCertificate(t *testing.T) {
	cert2, err := kon.LoadServerCertificate("192.168.1.194:443")
	if err != nil {
		t.Fatalf("error loading server certificate: %v", err)
	}

	kon.SaveCertificates("/tmp/certs.pem", cert2)

	certPool, _ := kon.LoadTrustStore("/tmp/certs.pem")

	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            certPool,
		ServerName:         cert2.DNSNames[0],
	}

	transport := &http.Transport{TLSClientConfig: config}

	httpClient := http.Client{Transport: transport}

	req, _ := http.NewRequest("GET", "https://tig.spilikin.dev/connector.sds", nil)
	req.SetBasicAuth(os.Getenv("KONNEKTOR_AUTH_BASIC_USERNAME"), os.Getenv("KONNEKTOR_AUTH_BASIC_PASSWORD"))
	resp, err := httpClient.Do(req)

	if err != nil {
		t.Errorf("error getting: %v", err)
	}

	t.Logf("resp: %v", resp)

}
