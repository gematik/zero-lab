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
	"bytes"
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
	keys := oidf.Keys{Sign: sign, Decrypt: agreement, Client: certificate}
	if files.MasterJWKPath != "" {
		// The master's key is public: an error may name the file and say what the parser found wrong.
		data, err := os.ReadFile(files.MasterJWKPath)
		if err != nil {
			return oidf.Keys{}, fmt.Errorf("master_jwk_path: %w", err)
		}
		if keys.Master, err = oidf.NewJwkFromJSON(string(data)); err != nil {
			return oidf.Keys{}, fmt.Errorf("master_jwk_path: %q: %w", files.MasterJWKPath, err)
		}
	}
	return keys, nil
}

// readECPrivateKey reads the one EC private key of a file, SEC 1 or PKCS #8. Errors name the file, never its content.
func readECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := readPEM(path, "EC PARAMETERS")
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
	return nil, fmt.Errorf("%q holds no EC private key", path)
}

// readClientCertificate reads the client key's certificate, the one PEM block of a file, and pairs it with the
// key, its Leaf parsed, as oidf publishes it as x5c. Whether the certificate is the key's is oidf's to judge.
func readClientCertificate(path string, key *ecdsa.PrivateKey) (tls.Certificate, error) {
	block, err := readPEM(path, "")
	if err != nil {
		return tls.Certificate{}, err
	}
	if block.Type != "CERTIFICATE" {
		return tls.Certificate{}, fmt.Errorf("%q holds no certificate", path)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%q holds no X.509 certificate", path)
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key, Leaf: leaf}, nil
}

// readPEM reads the one PEM block of a file, after at most one leading block of type skip, which `openssl ecparam
// -genkey` writes before the key. Anything but whitespace after the block is refused: a second key would otherwise
// be ignored, and which key counts would depend on the order in the file.
func readPEM(path, skip string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block != nil && skip != "" && block.Type == skip {
		if block, rest = pem.Decode(rest); block == nil {
			return nil, fmt.Errorf("%q holds nothing after its %s block", path, skip)
		}
	}
	if block == nil {
		return nil, fmt.Errorf("%q holds no PEM data", path)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%q holds something after its PEM block", path)
	}
	return block, nil
}
