package oidf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func TestNewRelyingParty(t *testing.T) {
	fedMasterURL := os.Getenv("OIDF_FEDMASTER_URL")
	if fedMasterURL == "" {
		t.Skip("OIDF_FEDMASTER_URL not set — skipping (NewRelyingPartyFromConfig fetches a live federation master)")
	}
	signKeyPath, _ := generateTempKeyFile()
	defer os.Remove(signKeyPath)
	encKeyPath, _ := generateTempKeyFile()
	defer os.Remove(encKeyPath)
	clientKeyPath, _ := generateTempKeyFile()
	defer os.Remove(clientKeyPath)
	clientCertPath, _ := generateCert(clientKeyPath)
	defer os.Remove(clientCertPath)

	jwk, err := NewJwkFromJson(`{
		"kty": "EC",
		"crv": "P-256",
		"x":   "cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs",
		"y":   "XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw",
		"kid": "puk_fedmaster_sig",
		"use": "sig",
		"alg": "ES256"
	}`)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &RelyingPartyConfig{
		Subject:              "https://example.com",
		FedMasterURL:         fedMasterURL,
		FedMasterJwk:         *jwk,
		SignKid:              "sign-kid",
		SignPrivateKeyPath:   signKeyPath,
		EncKid:               "enc-kid",
		EncPrivateKeyPath:    encKeyPath,
		ClientKid:            "client-kid",
		ClientPrivateKeyPath: clientKeyPath,
		ClientCertPath:       clientCertPath,
		MetadataTemplate: map[string]any{
			"openid_relying_party": map[string]any{
				"client_name": "https://example.com",
			},
		},
	}

	es, err := NewRelyingPartyFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := es.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}

	unverified, err := jwt.Parse(signed, jwt.WithVerify(false))
	if err != nil {
		t.Fatal(err)
	}

	var metaRaw any
	if err := unverified.Get("metadata", &metaRaw); err != nil {
		t.Fatal(err)
	}
	metadataMap, ok := metaRaw.(map[string]any)
	if !ok {
		t.Fatal("metadata not found")
	}

	t.Log(metadataMap)
}

func generateTempKeyFile() (string, error) {
	tmpfile, err := os.CreateTemp(``, `private-key-*.pem`)
	if err != nil {
		return "", err
	}

	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	prkDer, err := x509.MarshalECPrivateKey(prk)
	if err != nil {
		return "", err
	}

	err = pem.Encode(tmpfile, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: prkDer,
	})
	if err != nil {
		return "", err
	}

	return tmpfile.Name(), nil
}

func generateCert(keyfile string) (string, error) {
	keyJwks, err := jwk.ReadFile(keyfile, jwk.WithPEM(true))
	if err != nil {
		return "", err
	}

	prkJwk, ok := keyJwks.Key(0)
	if !ok {
		return "", errors.New("no key")
	}

	pukJwk, err := prkJwk.PublicKey()
	if err != nil {
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	var pubKey ecdsa.PublicKey
	if err := jwk.Export(pukJwk, &pubKey); err != nil {
		return "", err
	}
	var privKey ecdsa.PrivateKey
	if err := jwk.Export(prkJwk, &privKey); err != nil {
		return "", err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &pubKey, &privKey)
	if err != nil {
		return "", err
	}

	tmpfile, err := os.CreateTemp(``, `cert-*.pem`)
	if err != nil {
		return "", err
	}

	pem.Encode(tmpfile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return tmpfile.Name(), nil
}

func TestConfigFile(t *testing.T) {
	cfg, err := LoadRelyingPartyConfig("testdata/relying-party.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Subject != "https://rp.example.com" {
		t.Errorf("sub = %q", cfg.Subject)
	}
	if cfg.FedMasterURL != "https://app-ref.federationmaster.de" {
		t.Errorf("fed_master_url = %q", cfg.FedMasterURL)
	}
	if cfg.FedMasterJwk.Key == nil {
		t.Error("fed_master_jwk did not parse into a key")
	}

	rp, ok := cfg.MetadataTemplate["openid_relying_party"].(map[string]any)
	if !ok {
		t.Fatalf("metadata_template.openid_relying_party missing: %v", cfg.MetadataTemplate)
	}
	if rp["client_name"] != "Zero Trust Lab" {
		t.Errorf("client_name = %v", rp["client_name"])
	}

	// MetadataTemplate must stay JSON-serializable (it's marshaled downstream).
	if _, err := json.Marshal(cfg.MetadataTemplate); err != nil {
		t.Fatalf("metadata_template not JSON-serializable: %v", err)
	}
}
