package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/go-attestation/attest"
)

type Identity struct {
	FormatVersion             string      `json:"format_version"`
	tpm                       *attest.TPM `json:"-"`
	AttestationKeySealed      []byte      `json:"attestation_key"`
	AttestationCertificateRaw []byte      `json:"attestation_certificate"`
	ClientKeySealed           []byte      `json:"client_key"`
	ClientCertificateRaw      []byte      `json:"client_certificate"`
	attestationKey            *attest.AK  `json:"-"`
	clientKey                 *attest.Key `json:"-"`
}

func (id *Identity) LoadAK() (*attest.AK, error) {
	if id.attestationKey != nil {
		return id.attestationKey, nil
	}
	if id.AttestationKeySealed == nil {
		return nil, fmt.Errorf("no sealed AK")
	}
	ak, err := id.tpm.LoadAK(id.AttestationKeySealed)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	return ak, nil
}

func (id *Identity) UpdateAK(ak *attest.AK) error {
	var err error
	if id.AttestationKeySealed, err = ak.Marshal(); err != nil {
		return fmt.Errorf("sealing AK: %w", err)
	}
	id.attestationKey = ak
	return nil
}

func (id *Identity) LoadClientKey() (*attest.Key, error) {
	if id.clientKey != nil {
		return id.clientKey, nil
	}
	if id.ClientKeySealed == nil {
		return nil, fmt.Errorf("no sealed client key")
	}
	key, err := id.tpm.LoadKey(id.ClientKeySealed)
	if err != nil {
		return nil, fmt.Errorf("loading client key: %w", err)
	}
	id.clientKey = key
	return key, nil
}

func (id *Identity) UpdateClientKey(key *attest.Key) error {
	var err error
	if id.ClientKeySealed, err = key.Marshal(); err != nil {
		return fmt.Errorf("sealing key: %w", err)
	}
	id.clientKey = key
	return nil
}

func (id *Identity) AKCertificate() (*x509.Certificate, error) {
	if id.AttestationCertificateRaw == nil {
		return nil, fmt.Errorf("no attestation certificate")
	}
	return x509.ParseCertificate(id.AttestationCertificateRaw)
}

func (id *Identity) UpdateAKCertificate(cert *x509.Certificate) {
	id.AttestationCertificateRaw = cert.Raw
}

func (id *Identity) ClientCertificate() (*x509.Certificate, error) {
	if id.ClientCertificateRaw == nil {
		return nil, fmt.Errorf("no client certificate")
	}
	return x509.ParseCertificate(id.ClientCertificateRaw)
}

func (id *Identity) UpdateClientCertificate(cert *x509.Certificate) {
	id.ClientCertificateRaw = cert.Raw
}

func (id *Identity) ClientPrivateKey() (crypto.PrivateKey, error) {
	key, err := id.LoadClientKey()
	if err != nil {
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	return key.Private(key.Public())
}

func (id *Identity) save(path string) error {
	slog.Info("Saving identity", "path", path, "identity", id)
	identityBytes, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("marshaling identity: %w", err)
	}

	if err := os.WriteFile(path, identityBytes, 0600); err != nil {
		return fmt.Errorf("writing Identity: %w", err)
	}

	return nil
}

func (id *Identity) DeleteClientKey() {
	id.clientKey = nil
	id.ClientKeySealed = nil
}

func (id *Identity) DeleteAK() {
	id.DeleteClientKey()
	id.attestationKey = nil
	id.AttestationKeySealed = nil
}

func LoadIdentity(tpm *attest.TPM, path string) (*Identity, error) {
	identityBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading AK: %w", err)
	}

	identity := Identity{
		tpm: tpm,
	}

	if err := json.Unmarshal(identityBytes, &identity); err != nil {
		return nil, fmt.Errorf("unmarshaling identity: %w", err)
	}

	return &identity, nil
}
