package tcl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Identity struct {
	ClientPrK  util.Jwk
	ClientPuK  util.Jwk
	MtlsPrK    *ecdsa.PrivateKey `json:"-"`
	MtlsPrKRaw []byte
	MtlsCer    *x509.Certificate `json:"-"`
	MtlsCerRaw []byte
	ClientID   string
}

func loadOrCreateIdentityFile(path string) (*Identity, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return newIdentityFile(path)
	}
	return loadIdentityFile(path)
}

func loadIdentityFile(path string) (*Identity, error) {
	jsonId, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read identity file: %w", err)
	}
	identity := &Identity{}
	err = json.Unmarshal(jsonId, identity)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal identity: %w", err)
	}
	mtlsPrK, err := x509.ParseECPrivateKey(identity.MtlsPrKRaw)
	if err != nil {
		return nil, fmt.Errorf("could not parse mtls private key: %w", err)
	}
	identity.MtlsPrK = mtlsPrK

	if len(identity.MtlsCerRaw) > 0 {
		mtlsCer, err := x509.ParseCertificate(identity.MtlsCerRaw)
		if err != nil {
			return nil, fmt.Errorf("could not parse mtls certificate: %w", err)
		}
		identity.MtlsCer = mtlsCer
	}

	return identity, nil
}

func newIdentityFile(path string) (*Identity, error) {
	josePrK, err := newJOSEIdentity()
	if err != nil {
		return nil, fmt.Errorf("could not generate jose key: %w", err)
	}

	josePuK, err := josePrK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate jose public key: %w", err)
	}

	mtlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to genarate private keys, error: %s", err)
	}

	identity := &Identity{
		ClientPrK: util.Jwk{Key: josePrK},
		ClientPuK: util.Jwk{Key: josePuK},
		MtlsPrK:   mtlsKey,
	}

	return identity, saveIdentityFile(path, identity)
}

func saveIdentityFile(path string, identity *Identity) error {
	mtlsRaw, err := x509.MarshalECPrivateKey(identity.MtlsPrK)
	if err != nil {
		return fmt.Errorf("could not marshal mtls private key: %w", err)
	}
	identity.MtlsPrKRaw = mtlsRaw

	if identity.MtlsCer != nil {
		identity.MtlsCerRaw = identity.MtlsCer.Raw
	}

	jsonId, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("could not marshal identities: %w", err)
	}
	os.WriteFile(path, jsonId, 0600)
	return nil
}

func newJOSEIdentity() (jwk.Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %w", err)
	}
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create jwk from key: %w", err)
	}
	return jwkKey, nil
}
