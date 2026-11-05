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

package providers

import (
	"errors"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/openid"
)

type fakeClient struct {
	openid.Client
	issuer string
}

func (f fakeClient) Issuer() string { return f.issuer }

func fake(issuer, kind string) Provider {
	return Provider{Info: Info{Issuer: issuer, Name: issuer, Type: kind}, Client: fakeClient{issuer: issuer}}
}

func fakeKind(issuer string) Kind {
	return func(decode Decode, _ Env) (Built, error) {
		if err := decode(new(any)); err != nil {
			return Built{}, err
		}
		return Built{Providers: []Provider{fake(issuer, issuer)}}, nil
	}
}

func entry(key string) Entry {
	return Entry{Key: key, Decode: func(any) error { return nil }}
}

func TestAnOutdatedKeyStopsTheStart(t *testing.T) {
	_, err := Build([]Entry{entry("gemidp")}, Env{}, Kinds{"idpd": fakeKind("a")})
	if err == nil || !strings.Contains(err.Error(), `unknown key "gemidp"`) || !strings.Contains(err.Error(), "idpd") {
		t.Errorf("err = %v", err)
	}
}

func TestADecodeFailureStopsTheStart(t *testing.T) {
	failing := Entry{Key: "idpd", Decode: func(any) error { return errors.New("unknown field") }}
	if _, err := Build([]Entry{failing}, Env{}, Kinds{"idpd": fakeKind("a")}); err == nil {
		t.Error("a decode failure")
	}
}

func TestTheFilesOrderDecidesTheDefault(t *testing.T) {
	set, err := Build([]Entry{entry("b"), entry("a")}, Env{}, Kinds{"a": fakeKind("a"), "b": fakeKind("b")})
	if err != nil {
		t.Fatal(err)
	}
	first, err := set.Default()
	if err != nil {
		t.Fatal(err)
	}
	if first.Issuer != "b" {
		t.Errorf("default %s", first.Issuer)
	}
}

func TestListingAndLookup(t *testing.T) {
	set := New(nil, fake("https://a", "idpd"))
	if _, err := set.Provider(t.Context(), "https://a"); err != nil {
		t.Error(err)
	}
	if _, err := set.Provider(t.Context(), "https://b"); err == nil {
		t.Error("an unknown issuer without a federation")
	}
	infos, err := set.Providers(t.Context())
	if err != nil || len(infos) != 1 || infos[0].Type != "idpd" {
		t.Errorf("%+v, %v", infos, err)
	}
}
