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
	"context"
	"crypto"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/gematik/zero-lab/go/openid/providers"
)

// TypeOIDF is the provider type of a federation's members.
const TypeOIDF = "oidf"

// Provider implements [providers.Federation]: it resolves issuer in the federation.
func (rp *RelyingParty) Provider(ctx context.Context, issuer string) (providers.Provider, error) {
	client, err := rp.Client(ctx, issuer)
	if err != nil {
		return providers.Provider{}, err
	}
	current := client.provider()
	return providers.Provider{
		Issuer:  client.Issuer(),
		Name:    current.metadata.OrganizationName,
		LogoURI: current.metadata.LogoURI,
		Type:    TypeOIDF,
		Client:  client,
	}, nil
}

// Providers implements [providers.Federation].
func (rp *RelyingParty) Providers(ctx context.Context) ([]providers.Info, error) {
	idps, err := rp.Federation().FetchIdpList(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]providers.Info, 0, len(idps))
	for _, idp := range idps {
		infos = append(infos, providers.Info{Issuer: idp.Issuer, Name: idp.OrganizationName, LogoURI: idp.LogoURI, Type: TypeOIDF})
	}
	return infos, nil
}

// FileConfig is one relying party as a configuration file has it: its [RelyingPartyConfig] and, beside it, the files
// of its keys.
type FileConfig struct {
	RelyingPartyConfig `json:",inline" yaml:",inline"`
	KeyFiles           `json:",inline" yaml:",inline"`
}

// Validate reports a missing or misplaced field of the configuration or of its key files.
func (cfg *FileConfig) Validate() error {
	if err := cfg.RelyingPartyConfig.Validate(); err != nil {
		return err
	}
	return cfg.KeyFiles.Validate()
}

// KeyFiles names the files of the relying party's keys, which the host reads, not this package (keys.md rule 1): a
// configuration carries paths, never key material. SignKey signs the entity statement, EncKey decrypts the ID token,
// ClientKey authenticates the self_signed_tls_client_auth calls with its certificate.
type KeyFiles struct {
	SignKey   KeyFile `json:"sign_key" yaml:"sign_key"`
	EncKey    KeyFile `json:"enc_key" yaml:"enc_key"`
	ClientKey KeyFile `json:"client_key" yaml:"client_key"`
	// MasterJWKPath is the file of the federation master's signing key, one JWK as JSON (RFC 7517), for a master
	// the built-in table does not know. The key is public; it is a file all the same, so that the trust anchor is
	// read as the JSON it is in every format of the configuration, and replaced by replacing a file.
	MasterJWKPath string `json:"master_jwk_path,omitzero" yaml:"master_jwk_path,omitempty"`
}

// KeyFile names one key: KeyPEMPath its PEM private key and CertPEMPath its PEM certificate, which only the client
// key has. Kid is its key id; when empty, the key's RFC 7638 SHA-256 thumbprint is. A relying party registered with a
// federation master sets the kids it registered, or the IDP cannot find its keys: it looks them up by kid.
type KeyFile struct {
	KeyPEMPath  string `json:"key_pem_path" yaml:"key_pem_path"`
	CertPEMPath string `json:"cert_pem_path,omitzero" yaml:"cert_pem_path,omitempty"`
	Kid         string `json:"kid,omitzero" yaml:"kid,omitempty"`
}

// Validate reports a key without its file, a client key without its certificate, and a certificate named for
// another key, which would be ignored (servers.md rule 17).
func (files KeyFiles) Validate() error {
	for _, key := range []struct {
		name string
		file KeyFile
	}{{"sign_key", files.SignKey}, {"enc_key", files.EncKey}, {"client_key", files.ClientKey}} {
		if key.file.KeyPEMPath == "" {
			return fmt.Errorf("%s.key_pem_path is required", key.name)
		}
	}
	if files.ClientKey.CertPEMPath == "" {
		return errors.New("client_key.cert_pem_path is required (mTLS)")
	}
	if files.SignKey.CertPEMPath != "" || files.EncKey.CertPEMPath != "" {
		return errors.New("cert_pem_path belongs to client_key only")
	}
	return nil
}

// under resolves the relative paths of files against dir, the directory of the file that names them.
func (files KeyFiles) under(dir string) KeyFiles {
	join := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(dir, path)
	}
	for _, file := range []*KeyFile{&files.SignKey, &files.EncKey, &files.ClientKey} {
		file.KeyPEMPath, file.CertPEMPath = join(file.KeyPEMPath), join(file.CertPEMPath)
	}
	files.MasterJWKPath = join(files.MasterJWKPath)
	return files
}

// withKIDs gives keys the kids files name, and each key whose file names none its thumbprint.
func withKIDs(keys Keys, files KeyFiles) (Keys, error) {
	if err := keys.checkKeys(); err != nil {
		return Keys{}, err
	}
	encryption, err := encryptionPublicKey(keys.Decrypt)
	if err != nil {
		return Keys{}, err
	}
	for _, key := range []struct {
		kid        *string
		configured string
		public     crypto.PublicKey
	}{
		{&keys.SignKID, files.SignKey.Kid, keys.Sign.Public()},
		{&keys.DecryptKID, files.EncKey.Kid, encryption},
		{&keys.ClientKID, files.ClientKey.Kid, keys.Client.Leaf.PublicKey},
	} {
		*key.kid = key.configured
		if key.configured == "" {
			if *key.kid, err = thumbprint(key.public); err != nil {
				return Keys{}, err
			}
		}
	}
	return keys, nil
}

// Kind is the kind of a federation's relying party, one [FileConfig], with apiKey as its [RelyingPartyConfig.APIKey]
// and documents as its [RelyingPartyConfig.Documents]. keys loads the keys of the file's [KeyFiles], their relative
// paths resolved against the file's directory: the host reads them, this package reads no file. The kids of what keys
// returns are replaced by those of the file or the thumbprints. built, if not nil, gets the relying party, for a
// program that serves its entity statement too.
func Kind(apiKey string, documents Documents, keys func(KeyFiles) (Keys, error), built func(*RelyingParty)) providers.Kind {
	return func(decode providers.Decode, env providers.Env) (providers.Built, error) {
		if keys == nil {
			return providers.Built{}, errors.New("no loader of the relying party's keys")
		}
		file := new(FileConfig)
		if err := decode(file); err != nil {
			return providers.Built{}, err
		}
		if err := file.Validate(); err != nil {
			return providers.Built{}, fmt.Errorf("config validation failed: %w", err)
		}
		loaded, err := keys(file.under(env.BaseDir))
		if err != nil {
			return providers.Built{}, fmt.Errorf("load the relying party's keys: %w", err)
		}
		if loaded, err = withKIDs(loaded, file.KeyFiles); err != nil {
			return providers.Built{}, err
		}
		config := &file.RelyingPartyConfig
		config.APIKey = apiKey
		config.HTTPClient = env.HTTPClient
		config.Documents = documents
		// providers.Build runs at start-up and hands no context down; the bound keeps a master that does not
		// answer from holding the start for longer than one fetch may take.
		ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPTimeout)
		defer cancel()
		rp, err := New(ctx, config, loaded)
		if err != nil {
			return providers.Built{}, err
		}
		if built != nil {
			built(rp)
		}
		return providers.Built{Federation: rp}, nil
	}
}
