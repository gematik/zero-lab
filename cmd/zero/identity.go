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
	FormatVersion string      `json:"format_version"`
	tpm           *attest.TPM `json:"-"`
	SealedAK      []byte      `json:"sealed_ak"`
	SealedKey     []byte      `json:"sealed_key"`
	CertRaw       []byte      `json:"cert_raw"`
	ak            *attest.AK  `json:"-"`
	key           *attest.Key `json:"-"`
}

func (id *Identity) LoadAK() (*attest.AK, error) {
	if id.ak != nil {
		return id.ak, nil
	}
	if id.SealedAK == nil {
		return nil, fmt.Errorf("no sealed AK")
	}
	ak, err := id.tpm.LoadAK(id.SealedAK)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	return ak, nil
}

func (id *Identity) UpdateAK(ak *attest.AK) error {
	var err error
	if id.SealedAK, err = ak.Marshal(); err != nil {
		return fmt.Errorf("sealing AK: %w", err)
	}
	id.ak = ak
	return nil
}

func (id *Identity) LoadKey() (*attest.Key, error) {
	if id.key != nil {
		return id.key, nil
	}
	if id.SealedKey == nil {
		return nil, fmt.Errorf("no sealed key")
	}
	key, err := id.tpm.LoadKey(id.SealedKey)
	if err != nil {
		return nil, fmt.Errorf("loading key: %w", err)
	}
	id.key = key
	return key, nil
}

func (id *Identity) UpdateKey(key *attest.Key) error {
	var err error
	if id.SealedKey, err = key.Marshal(); err != nil {
		return fmt.Errorf("sealing key: %w", err)
	}
	id.key = key
	return nil
}

func (id *Identity) Certificate() (*x509.Certificate, error) {
	if id.CertRaw == nil {
		return nil, fmt.Errorf("no certificate")
	}
	return x509.ParseCertificate(id.CertRaw)
}

func (id *Identity) UpdateCertificate(cert *x509.Certificate) {
	id.CertRaw = cert.Raw
}

func (id *Identity) PrivateKey() (crypto.PrivateKey, error) {
	key, err := id.LoadKey()
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
