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

// Package epatest holds test doubles for the epa package's identity backends: an
// Identity that signs nothing real and an Authenticator that answers with a fixed code.
// Tests of the proxy, the portal and the session guards use them instead of the ti tool.
package epatest

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/gematik/zero-lab/go/epa/ti"
)

// Identity is an epa.Identity whose "signatures" are unsigned compact JWS-shaped
// strings: header and claims are real, the signature part is `fake`.
type Identity struct {
	SubjectDN  string
	Telematik  string
	CertDER    []byte
	Admitted   *ti.Admission
	Signed     []map[string]any
	SignHeader []map[string]any
	// Err, when set, is what SignJWT returns.
	Err error
}

// SignJWT records header and claims and returns `<header>.<claims>.fake`.
func (f *Identity) SignJWT(_ context.Context, header map[string]any, claims map[string]any) (string, error) {
	if f.Err != nil {
		return "", f.Err
	}
	f.SignHeader = append(f.SignHeader, header)
	f.Signed = append(f.Signed, claims)
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(h) + "." + enc(c) + ".fake", nil
}

func (f *Identity) CertificateDER() []byte   { return f.CertDER }
func (f *Identity) Subject() string          { return f.SubjectDN }
func (f *Identity) TelematikID() string      { return f.Telematik }
func (f *Identity) Admission() *ti.Admission { return f.Admitted }

// Authenticator answers every authorization URL with Code.
type Authenticator struct {
	Code  string
	State string
	URLs  []string
	Err   error
}

// Authenticate records authURL and returns the fixed code.
func (f *Authenticator) Authenticate(_ context.Context, authURL string) (*ti.CodeRedirect, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	f.URLs = append(f.URLs, authURL)
	return &ti.CodeRedirect{Code: f.Code, State: f.State, URL: "https://rp.test/cb?code=" + f.Code}, nil
}
