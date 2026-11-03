// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package oidf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// unverifiedPayload reads the claims of a compact JWS, for a test that has already got what it needs from the signer.
func unverifiedPayload(t *testing.T, signed []byte) []byte {
	t.Helper()
	parts := strings.Split(string(signed), ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", signed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestNewRelyingParty(t *testing.T) {
	fedMasterURL := os.Getenv("OIDF_FEDMASTER_URL")
	if fedMasterURL == "" {
		t.Skip("OIDF_FEDMASTER_URL not set — skipping (NewRelyingParty fetches a live federation master)")
	}
	signKeyPath, _ := generateTempKeyFile()
	defer os.Remove(signKeyPath)
	encKeyPath, _ := generateTempKeyFile()
	defer os.Remove(encKeyPath)
	clientKeyPath, _ := generateTempKeyFile()
	defer os.Remove(clientKeyPath)
	clientCertPath, _ := generateCert(clientKeyPath)
	defer os.Remove(clientCertPath)

	fedMasterJwk, err := NewJwkFromJSON(`{
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
		Subject:      "https://example.com",
		FedMasterURL: fedMasterURL,
		FedMasterJWK: fedMasterJwk,
		SignKey:      KeyConfig{KeyPEMPath: signKeyPath},
		EncKey:       KeyConfig{KeyPEMPath: encKeyPath},
		ClientKey:    KeyConfig{KeyPEMPath: clientKeyPath, CertPEMPath: clientCertPath},
		RelyingParty: RelyingPartyMetadata{
			ClientName:   "https://example.com",
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	es, err := NewRelyingParty(cfg, "")
	if err != nil {
		t.Fatal(err)
	}

	signed, err := es.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}

	var claims struct {
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Metadata == nil {
		t.Fatal("metadata not found")
	}

	t.Log(claims.Metadata)
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
	keyData, err := os.ReadFile(keyfile)
	if err != nil {
		return "", err
	}
	parsed, err := parsePrivateKeyPEM(keyData)
	if err != nil {
		return "", err
	}
	privKey, ok := parsed.Key.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("not an EC key")
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return "", err
	}

	tmpfile, err := os.CreateTemp(``, `cert-*.pem`)
	if err != nil {
		return "", err
	}

	if err := pem.Encode(tmpfile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		return "", err
	}

	return tmpfile.Name(), nil
}

func TestBuildMetadataFillsTheDefaultsAConfigOmits(t *testing.T) {
	cfg := &RelyingPartyConfig{RelyingParty: RelyingPartyMetadata{ClientName: "c", RedirectURIs: []string{"https://rp/cb"}}}
	md := cfg.buildMetadata().OpenidRelyingParty
	if md.TokenEndpointAuthMethod != "self_signed_tls_client_auth" || md.IDTokenEncryptedResponseEnc != "A256GCM" {
		t.Errorf("defaults not applied: %+v", md)
	}
}
