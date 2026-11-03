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
// lookup. It knows no provider beyond plain OIDC and no file format: the program reads its file and passes
// [Entry] values, and the other providers come in as a [Kind], so it carries only the modules of the kinds it uses.
package providers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/gematik/zero-lab/go/openid"
)

// Info describes a provider for a chooser.
type Info struct {
	Issuer  string `json:"issuer"`
	Name    string `json:"name"`
	LogoURI string `json:"logo_uri"`
	Type    string `json:"type"`
}

// TypeOIDC is the [Info.Type] of a plain OpenID Connect provider.
const TypeOIDC = "oidc"

// Provider is a client and what a chooser shows of it.
type Provider struct {
	Info
	Client openid.Client
}

// Federation is a source of providers that resolves an issuer on demand.
type Federation interface {
	Provider(ctx context.Context, issuer string) (Provider, error)
	Providers(ctx context.Context) ([]Info, error)
}

// Env is what a [Kind] may need from the program and the file.
type Env struct {
	// BaseDir is the file's directory, which relative paths in its entries resolve against.
	BaseDir string
	// RedirectURI is used by an entry without one of its own.
	RedirectURI string
}

// Decode reads an entry's value into a typed configuration. The program supplies it and decides the format. It
// must refuse unknown fields, so an outdated file stops the start instead of silently losing a provider.
type Decode func(v any) error

// Entry is one top-level key of the providers file.
type Entry struct {
	Key    string
	Decode Decode
}

// Built is what a [Kind] made of its part of the file.
type Built struct {
	Providers  []Provider
	Federation Federation
}

// Kind builds the providers of one top-level key of the file.
type Kind func(decode Decode, env Env) (Built, error)

// Kinds names the kinds a program accepts, by their key in the file.
type Kinds map[string]Kind

// Set is the providers of a server.
type Set struct {
	providers  []Provider
	federation Federation
}

// New makes a Set directly; federation may be nil.
func New(federation Federation, providers ...Provider) *Set {
	return &Set{providers: providers, federation: federation}
}

// Build makes a Set of entries in their file's order, since the first provider is the default. An unknown key is
// an error.
func Build(entries []Entry, env Env, kinds Kinds) (*Set, error) {
	set := New(nil)
	for _, entry := range entries {
		kind, ok := kinds[entry.Key]
		if !ok {
			known := make([]string, 0, len(kinds))
			for key := range kinds {
				known = append(known, key)
			}
			slices.Sort(known)
			return nil, fmt.Errorf("unknown key %q, known are %s", entry.Key, strings.Join(known, ", "))
		}
		built, err := kind(entry.Decode, env)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Key, err)
		}
		set.providers = append(set.providers, built.Providers...)
		if built.Federation != nil {
			if set.federation != nil {
				return nil, errors.New("more than one federation")
			}
			set.federation = built.Federation
		}
	}
	return set, nil
}

// OIDC is the kind of plain OpenID Connect providers, a list of [openid.Config].
func OIDC(decode Decode, env Env) (Built, error) {
	var configs []openid.Config
	if err := decode(&configs); err != nil {
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
		client, err := openid.NewClient(config)
		if err != nil {
			return Built{}, fmt.Errorf("[%d] (%s): %w", i, config.Issuer, err)
		}
		name := config.Name
		if name == "" {
			name = "OpenID Connect"
		}
		built.Providers = append(built.Providers, Provider{
			Info:   Info{Issuer: client.Issuer(), Name: name, LogoURI: config.LogoURI, Type: TypeOIDC},
			Client: client,
		})
		slog.Info("configured openid provider", "type", TypeOIDC, "name", name, "issuer", client.Issuer())
	}
	return built, nil
}

// Add adds a provider after those already there.
func (s *Set) Add(provider Provider) {
	s.providers = append(s.providers, provider)
}

// Configured are the configured providers, the first being the default; a federation's are not among them.
func (s *Set) Configured() []Provider {
	return s.providers
}

// Federation is the set's federation, nil if it has none.
func (s *Set) Federation() Federation {
	return s.federation
}

// Empty says the set has nothing to log in with.
func (s *Set) Empty() bool {
	return len(s.providers) == 0 && s.federation == nil
}

// Provider finds the provider of issuer: a configured one, else what the federation resolves.
func (s *Set) Provider(ctx context.Context, issuer string) (Provider, error) {
	for _, provider := range s.providers {
		if provider.Issuer == issuer {
			return provider, nil
		}
	}
	if s.federation != nil {
		return s.federation.Provider(ctx, issuer)
	}
	return Provider{}, fmt.Errorf("unknown issuer: %q", issuer)
}

// Default is the first configured provider.
func (s *Set) Default() (Provider, error) {
	if len(s.providers) == 0 {
		return Provider{}, errors.New("no default provider configured; choose one")
	}
	return s.providers[0], nil
}

// Providers lists all providers for a chooser, asking the federation for its own.
func (s *Set) Providers(ctx context.Context) ([]Info, error) {
	infos := make([]Info, 0, len(s.providers))
	for _, provider := range s.providers {
		infos = append(infos, provider.Info)
	}
	if s.federation != nil {
		federated, err := s.federation.Providers(ctx)
		if err != nil {
			return nil, fmt.Errorf("list the federation's providers: %w", err)
		}
		infos = append(infos, federated...)
	}
	return infos, nil
}
