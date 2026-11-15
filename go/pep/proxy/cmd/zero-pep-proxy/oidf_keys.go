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
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/oidf"
)

// loadOIDFKeys reads the relying party's keys from the PEM files the configuration names, at the edge, so that the
// library reads no file. The keys are software keys in memory; oidf takes their functions, a crypto.Signer, an ECDH
// key agreement and a tls.Certificate, and sets their kids.
func loadOIDFKeys(files oidf.KeyFiles) (oidf.Keys, error) {
	sign, err := readECPrivateKey(files.SignKey.KeyPEMPath)
	if err != nil {
		return oidf.Keys{}, fmt.Errorf("sign_key: %w", err)
	}
	enc, err := readECPrivateKey(files.EncKey.KeyPEMPath)
	if err != nil {
		return oidf.Keys{}, fmt.Errorf("enc_key: %w", err)
	}
	agreement, err := enc.ECDH()
	if err != nil {
		return oidf.Keys{}, fmt.Errorf("enc_key: %w", err)
	}
	client, err := readECPrivateKey(files.ClientKey.KeyPEMPath)
	if err != nil {
		return oidf.Keys{}, fmt.Errorf("client_key: %w", err)
	}
	certificate, err := readClientCertificate(files.ClientKey.CertPEMPath, client)
	if err != nil {
		return oidf.Keys{}, fmt.Errorf("client_key: %w", err)
	}
	return oidf.Keys{Sign: sign, Decrypt: agreement, Client: certificate}, nil
}

// readECPrivateKey reads an EC private key from the first PEM block of a file, SEC 1 or PKCS #8. Errors name the
// file, never its content.
func readECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%q holds no SEC 1 EC private key", path)
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%q holds no PKCS #8 private key", path)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%q holds a %T, no EC private key", path, parsed)
		}
		return key, nil
	}
	return nil, fmt.Errorf("%q holds a PEM block %q, no EC private key", path, block.Type)
}

// readClientCertificate reads the client key's certificate from the first PEM block of a file and pairs it with the
// key, its Leaf parsed, as oidf publishes it as x5c. Whether the certificate is the key's is oidf's to judge.
func readClientCertificate(path string, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	block, err := readPEM(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	if block.Type != "CERTIFICATE" {
		return tls.Certificate{}, fmt.Errorf("%q holds a PEM block %q, no certificate", path, block.Type)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%q: %w", path, err)
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}, nil
}

func readPEM(path string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%q holds no PEM data", path)
	}
	return block, nil
}
