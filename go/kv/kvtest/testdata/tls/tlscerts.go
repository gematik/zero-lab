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

// Command tlscerts writes TEST-ONLY certificates for a database with TLS into a directory: a CA, a server
// certificate for the name kv-test-db, and a client certificate. The keys protect nothing and are readable
// by everyone, so that a database in a container can read them; they are made anew for each run and never
// committed.
//
//	go run kv/kvtest/testdata/tls/tlscerts.go <directory>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ServerName is the one name the server's certificate is for. The tests reach the database by an address
// that is not this name, so that verifying the name is seen to matter.
const ServerName = "kv-test-db"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tlscerts <directory>")
		os.Exit(2)
	}
	if err := write(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func write(dir string) error {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TEST ONLY kv test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER); err != nil {
		return err
	}
	leaves := []struct {
		file string
		cert *x509.Certificate
	}{
		{"server", &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: ServerName},
			DNSNames:     []string{ServerName},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}},
		{"client", &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "kv_mtls"},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}},
	}
	for _, leaf := range leaves {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		leaf.cert.NotBefore, leaf.cert.NotAfter = ca.NotBefore, ca.NotAfter
		leaf.cert.KeyUsage = x509.KeyUsageDigitalSignature
		der, err := x509.CreateCertificate(rand.Reader, leaf.cert, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, leaf.file+".pem"), "CERTIFICATE", der); err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, leaf.file+"-key.pem"), "PRIVATE KEY", keyDER); err != nil {
			return err
		}
	}
	return nil
}

func writePEM(path, kind string, der []byte) error {
	// Readable by everyone: the database in the container runs as another user, and the key protects nothing.
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o644)
}
