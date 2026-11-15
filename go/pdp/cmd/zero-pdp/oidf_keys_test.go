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

package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/oidf/oidftest"
	"github.com/gematik/zero-lab/go/openid/providers"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sec1(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func selfSignedDER(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// keyFiles writes the three keys of a relying party into dir, the signing key as SEC 1 and the others as PKCS #8, and
// names them with paths relative to dir.
func keyFiles(t *testing.T, dir string) (oidf.KeyFiles, [3]*ecdsa.PrivateKey, []byte) {
	t.Helper()
	keys := [3]*ecdsa.PrivateKey{newKey(t), newKey(t), newKey(t)}
	writePEM(t, dir, "sign.pem", "EC PRIVATE KEY", sec1(t, keys[0]))
	writePEM(t, dir, "enc.pem", "PRIVATE KEY", pkcs8(t, keys[1]))
	writePEM(t, dir, "client.pem", "PRIVATE KEY", pkcs8(t, keys[2]))
	certificate := selfSignedDER(t, keys[2])
	writePEM(t, dir, "client-cert.pem", "CERTIFICATE", certificate)
	return oidf.KeyFiles{
		SignKey:   oidf.KeyFile{KeyPEMPath: "sign.pem"},
		EncKey:    oidf.KeyFile{KeyPEMPath: "enc.pem"},
		ClientKey: oidf.KeyFile{KeyPEMPath: "client.pem", CertPEMPath: "client-cert.pem"},
	}, keys, certificate
}

// inDir is files with their paths joined to dir, as oidf.Kind hands them to the loader.
func inDir(dir string, files oidf.KeyFiles) oidf.KeyFiles {
	for _, file := range []*oidf.KeyFile{&files.SignKey, &files.EncKey, &files.ClientKey} {
		file.KeyPEMPath = filepath.Join(dir, file.KeyPEMPath)
		if file.CertPEMPath != "" {
			file.CertPEMPath = filepath.Join(dir, file.CertPEMPath)
		}
	}
	return files
}

// TestLoadOIDFKeysReadsSEC1AndPKCS8 proves the loader's file formats, an internal invariant of the host: an EC key
// as SEC 1 or PKCS #8, and the client certificate with its Leaf parsed.
func TestLoadOIDFKeysReadsSEC1AndPKCS8(t *testing.T) {
	dir := t.TempDir()
	files, want, certificate := keyFiles(t, dir)
	keys, err := loadOIDFKeys(inDir(dir, files))
	if err != nil {
		t.Fatal(err)
	}
	if sign, ok := keys.Sign.(*ecdsa.PrivateKey); !ok || !sign.Equal(want[0]) {
		t.Error("another signing key")
	}
	wantAgreement, err := want[1].ECDH()
	if err != nil {
		t.Fatal(err)
	}
	if public, ok := keys.Decrypt.Public().(*ecdh.PublicKey); !ok || !public.Equal(wantAgreement.PublicKey()) {
		t.Error("another ID token key")
	}
	if client, ok := keys.Client.PrivateKey.(*ecdsa.PrivateKey); !ok || !client.Equal(want[2]) {
		t.Error("another client key")
	}
	if keys.Client.Leaf == nil || len(keys.Client.Certificate) != 1 || string(keys.Client.Certificate[0]) != string(certificate) || string(keys.Client.Leaf.Raw) != string(certificate) {
		t.Error("another client certificate, or no Leaf")
	}
	if keys.SignKID != "" || keys.DecryptKID != "" || keys.ClientKID != "" {
		t.Error("the loader set a kid, which is oidf's to set")
	}
}

// TestLoadOIDFKeysRefusesWhatIsNoECPrivateKey proves that the loader takes EC private keys only, and that its errors
// name the file and the key it was for but quote nothing of the file.
func TestLoadOIDFKeysRefusesWhatIsNoECPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(newKey(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		blockType string
		der       []byte
	}{
		"an RSA key as PKCS #1":  {"RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)},
		"an RSA key as PKCS #8":  {"PRIVATE KEY", pkcs8(t, rsaKey)},
		"a public key":           {"PUBLIC KEY", public},
		"a certificate":          {"CERTIFICATE", selfSignedDER(t, newKey(t))},
		"PKCS #8 under SEC 1":    {"EC PRIVATE KEY", pkcs8(t, newKey(t))},
		"garbage as a PEM block": {"PRIVATE KEY", []byte("not DER")},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files, _, _ := keyFiles(t, dir)
			path := writePEM(t, dir, "enc.pem", c.blockType, c.der)
			_, err := loadOIDFKeys(inDir(dir, files))
			if err == nil || !strings.HasPrefix(err.Error(), "enc_key: ") || !strings.Contains(err.Error(), path) {
				t.Errorf("err = %v", err)
			}
		})
	}
	for name, content := range map[string]string{"no PEM": "no PEM here", "an empty file": ""} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files, _, _ := keyFiles(t, dir)
			path := filepath.Join(dir, "sign.pem")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadOIDFKeys(inDir(dir, files))
			if err == nil || !strings.HasPrefix(err.Error(), "sign_key: ") || !strings.Contains(err.Error(), path) || content != "" && strings.Contains(err.Error(), content) {
				t.Errorf("err = %v", err)
			}
		})
	}
	dir := t.TempDir()
	files, _, _ := keyFiles(t, dir)
	files.ClientKey.KeyPEMPath = "missing.pem"
	if _, err := loadOIDFKeys(inDir(dir, files)); err == nil || !strings.HasPrefix(err.Error(), "client_key: ") {
		t.Errorf("a missing file: %v", err)
	}
}

// TestLoadOIDFKeysRefusesACertificateFileWithoutACertificate proves that the client certificate is read from a
// CERTIFICATE block only.
func TestLoadOIDFKeysRefusesACertificateFileWithoutACertificate(t *testing.T) {
	for name, c := range map[string]struct {
		blockType string
		der       []byte
	}{
		"a private key":      {"PRIVATE KEY", pkcs8(t, newKey(t))},
		"garbage as a block": {"CERTIFICATE", []byte("not DER")},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files, _, _ := keyFiles(t, dir)
			path := writePEM(t, dir, "client-cert.pem", c.blockType, c.der)
			if _, err := loadOIDFKeys(inDir(dir, files)); err == nil || !strings.HasPrefix(err.Error(), "client_key: ") || !strings.Contains(err.Error(), path) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// TestTheLoadedKeysBuildARelyingParty proves the host's part of keys.md rule 1: oidf.Kind hands the key files to
// loadOIDFKeys, which reads them, and the relying party signs with the signing key of the files.
func TestTheLoadedKeysBuildARelyingParty(t *testing.T) {
	federation := oidftest.New(t)
	dir := t.TempDir()
	files, keys, _ := keyFiles(t, dir)
	files.SignKey.Kid = "sign"
	decode := func(v any) error {
		target, ok := v.(*oidf.FileConfig)
		if !ok {
			return fmt.Errorf("decode into a %T", v)
		}
		target.KeyFiles = files
		target.RelyingPartyConfig = oidf.RelyingPartyConfig{
			Subject:      "https://rp.example",
			FedMasterURL: federation.MasterURL(),
			FedMasterJWK: &oidf.Jwk{Key: &federation.TrustAnchor().Keys[0]},
			RelyingParty: oidf.RelyingPartyMetadata{
				ClientName:          "rp",
				OrganizationName:    "Example",
				RedirectURIs:        []string{"https://rp.example/cb"},
				Keywords:            []string{"product_type:example", "product_type_version:0.0.0"},
				Contacts:            []string{"support@example.invalid"},
				TIFeaturesSupported: &oidf.TIFeatures{IDTokenVersionSupported: []string{"1.0.0"}},
			},
			FederationEntity: oidf.FederationEntity{Name: "rp"},
		}
		return nil
	}
	var rp *oidf.RelyingParty
	kind := oidf.Kind("", oidf.NewMemoryDocuments(16, nil), loadOIDFKeys, func(built *oidf.RelyingParty) { rp = built })
	if _, err := kind(decode, providers.Env{BaseDir: dir, HTTPClient: federation.Client()}); err != nil {
		t.Fatal(err)
	}
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	object, err := jose.ParseSigned(string(signed), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if kid := object.Signatures[0].Protected.KeyID; kid != "sign" {
		t.Errorf("signed under kid %q", kid)
	}
	if _, err := object.Verify(keys[0].Public()); err != nil {
		t.Errorf("not signed by the signing key of the files: %v", err)
	}
}
