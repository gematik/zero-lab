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
