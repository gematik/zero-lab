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

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestNewRelyingParty(t *testing.T) {
	signKeyPath, _ := generateTempKeyFile()
	defer os.Remove(signKeyPath)
	encKeyPath, _ := generateTempKeyFile()
	defer os.Remove(encKeyPath)
	clientKeyPath, _ := generateTempKeyFile()
	defer os.Remove(clientKeyPath)
	clientCertPath, _ := generateCert(clientKeyPath)
	defer os.Remove(clientCertPath)

	cfg := &RelyingPartyConfig{
		Url: "https://example.com",
		FedMasterJwks: map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"crv": "P-256",
					"x":   "cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs",
					"y":   "XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw",
					"kid": "puk_fedmaster_sig",
					"use": "sig",
					"alg": "ES256",
				},
			},
		},
		FedMasterURL:         "https://fed.example.com",
		SignKid:              "sign-kid",
		SignPrivateKeyPath:   signKeyPath,
		EncKid:               "enc-kid",
		EncPrivateKeyPath:    encKeyPath,
		ClientKid:            "client-kid",
		ClientPrivateKeyPath: clientKeyPath,
		ClientCertPath:       clientCertPath,
		MetadataTemplate: map[string]interface{}{
			"openid_relying_party": map[string]interface{}{
				"client_name": "https://example.com",
			},
		},
	}

	es, err := NewRelyingPartyFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := es.Sign()
	if err != nil {
		t.Fatal(err)
	}

	unverified, err := jwt.Parse(signed, jwt.WithVerify(false))
	if err != nil {
		t.Fatal(err)
	}

	metadataMap, ok := unverified.PrivateClaims()["metadata"].(map[string]interface{})
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pukJwk.Raw(&ecdsa.PublicKey{}), prkJwk.Raw(&ecdsa.PrivateKey{}))

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
	cfg, err := LoadRelyingPartyConfig("../../relying-party-reg.yaml")
	if err != nil {
		t.Fatal(err)
	}

	m, err := json.Marshal(cfg.MetadataTemplate)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(m))
}
