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

// Package providers holds the identity providers a server logs users in with: one file format, listing and
// lookup. It knows no provider beyond plain OIDC; the others come in as a [Kind], so a program carries only the
// modules of the kinds it uses.
package providers

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// Info describes a provider for a chooser.
type Info struct {
	Issuer  string `json:"issuer"`
	Name    string `json:"name"`
	LogoURI string `json:"logo_uri"`
	Type    string `json:"type"`
}

// TypeOIDC is the [Info.Type] of a client that names no other type.
const TypeOIDC = "oidc"

// Typed is a client that names its type for [Info.Type].
type Typed interface {
	ProviderType() string
}

// TypeOf is the type a client goes by.
func TypeOf(client oidc.Client) string {
	if typed, ok := client.(Typed); ok {
		return typed.ProviderType()
	}
	return TypeOIDC
}

// Federation is a source of providers that resolves an issuer on demand.
type Federation interface {
	NewClient(issuer string) (oidc.Client, error)
	Providers() ([]Info, error)
}

// Env is what a [Kind] may need from the program and the file.
type Env struct {
	// BaseDir is the file's directory, which relative paths in its entries resolve against.
	BaseDir string
	// RedirectURI is used by an entry without one of its own.
	RedirectURI string
}

// Built is what a [Kind] made of its part of the file.
type Built struct {
	Clients    []oidc.Client
	Federation Federation
}

// Kind builds the providers of one top-level key of the file.
type Kind func(node *yaml.Node, env Env) (Built, error)

// Kinds names the kinds a program accepts, by their key in the file.
type Kinds map[string]Kind

// Set is the providers of a server.
type Set struct {
	clients    []oidc.Client
	federation Federation
}

// New makes a Set directly; federation may be nil.
func New(federation Federation, clients ...oidc.Client) *Set {
	return &Set{clients: clients, federation: federation}
}

// Load reads the providers file. ${VAR} placeholders expand from the environment, and an unknown key is an
// error at any level, so an outdated file stops the start instead of silently losing a provider.
func Load(path string, env Env, kinds Kinds) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read providers %q: %w", path, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &document); err != nil {
		return nil, fmt.Errorf("parse providers %q: %w", path, err)
	}
	env.BaseDir = filepath.Dir(path)
	set := New(nil)
	if len(document.Content) == 0 {
		return set, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("providers %q: not a mapping", path)
	}
	// In the file's order, since the first provider is the default.
	for i := 0; i+1 < len(root.Content); i += 2 {
		name := root.Content[i].Value
		kind, ok := kinds[name]
		if !ok {
			known := make([]string, 0, len(kinds))
			for key := range kinds {
				known = append(known, key)
			}
			slices.Sort(known)
			return nil, fmt.Errorf("providers %q: unknown key %q, known are %s", path, name, strings.Join(known, ", "))
		}
		built, err := kind(root.Content[i+1], env)
		if err != nil {
			return nil, fmt.Errorf("providers %q: %s: %w", path, name, err)
		}
		set.clients = append(set.clients, built.Clients...)
		if built.Federation != nil {
			if set.federation != nil {
				return nil, fmt.Errorf("providers %q: more than one federation", path)
			}
			set.federation = built.Federation
		}
	}
	return set, nil
}

// Decode reads a node strictly into v: yaml.v3's Node.Decode cannot refuse unknown fields, a Decoder can.
func Decode(node *yaml.Node, v any) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(v)
}

// OIDC is the kind of plain OpenID Connect providers, a list of [oidc.Config].
func OIDC(node *yaml.Node, env Env) (Built, error) {
	var configs []oidc.Config
	if err := Decode(node, &configs); err != nil {
		return Built{}, err
	}
	var built Built
	for i, config := range configs {
		if config.RedirectURI == "" {
			config.RedirectURI = env.RedirectURI
		}
		if err := config.Validate(); err != nil {
			return Built{}, fmt.Errorf("[%d]: %w", i, err)
		}
		client, err := oidc.NewClient(config)
		if err != nil {
			return Built{}, fmt.Errorf("[%d] (%s): %w", i, config.Issuer, err)
		}
		built.Clients = append(built.Clients, client)
		slog.Info("configured openid provider", "type", TypeOIDC, "name", client.Name(), "issuer", client.Issuer())
	}
	return built, nil
}

// Add adds a client after those already there.
func (s *Set) Add(client oidc.Client) {
	s.clients = append(s.clients, client)
}

// Clients are the configured clients, the first being the default; a federation's are not among them.
func (s *Set) Clients() []oidc.Client {
	return s.clients
}

// Federation is the set's federation, nil if it has none.
func (s *Set) Federation() Federation {
	return s.federation
}

// Empty says the set has nothing to log in with.
func (s *Set) Empty() bool {
	return len(s.clients) == 0 && s.federation == nil
}

// Client finds the client of issuer: a configured one, else what the federation resolves.
func (s *Set) Client(issuer string) (oidc.Client, error) {
	for _, client := range s.clients {
		if client.Issuer() == issuer {
			return client, nil
		}
	}
	if s.federation != nil {
		return s.federation.NewClient(issuer)
	}
	return nil, fmt.Errorf("unknown issuer: %q", issuer)
}

// Default is the first configured client.
func (s *Set) Default() (oidc.Client, error) {
	if len(s.clients) == 0 {
		return nil, errors.New("no default provider configured; choose one")
	}
	return s.clients[0], nil
}

// Providers lists all providers for a chooser, asking the federation for its own.
func (s *Set) Providers() ([]Info, error) {
	infos := make([]Info, 0, len(s.clients))
	for _, client := range s.clients {
		infos = append(infos, InfoOf(client))
	}
	if s.federation != nil {
		federated, err := s.federation.Providers()
		if err != nil {
			return nil, fmt.Errorf("list the federation's providers: %w", err)
		}
		infos = append(infos, federated...)
	}
	return infos, nil
}

// InfoOf describes one client.
func InfoOf(client oidc.Client) Info {
	return Info{Issuer: client.Issuer(), Name: client.Name(), LogoURI: client.LogoURI(), Type: TypeOf(client)}
}
