package epa

import (
	"context"
	"strings"

	"github.com/gematik/zero-lab/go/epa/ti"
)

// Identity is the SMC-B AUT identity a Session signs with: ePA's clientAttest and
// entitlement JWTs, and the IDP-Dienst challenge through an [Authenticator]. The key is
// not in this process: [ti.Identity] signs through the Rust tool, with a PKCS#12 file, a
// PEM pair or a card at the Konnektor; tests implement their own.
type Identity interface {
	// SignJWT returns a compact JWS over claims: `alg` from the key, `x5c` the
	// certificate, `typ` and the other members from header.
	SignJWT(ctx context.Context, header map[string]any, claims map[string]any) (string, error)
	// CertificateDER is the AUT certificate.
	CertificateDER() []byte
	// Subject is the certificate's subject DN (RFC 4514).
	Subject() string
	// TelematikID is the admission statement's registration number, empty without one.
	TelematikID() string
	// Admission is the admission statement, nil without one.
	Admission() *ti.Admission
}

// Admission is what the certificate says about its holder, as /info shows it.
type Admission = ti.Admission

// Authenticator turns the Aktensystem's authorization URL into an authorization code
// at the IDP-Dienst: [ti.Authenticator] in production, a fake in tests.
type Authenticator interface {
	Authenticate(ctx context.Context, authURL string) (*CodeRedirect, error)
}

// CodeRedirect is the IDP's answer: the code the Aktensystem consumes.
type CodeRedirect = ti.CodeRedirect

// SecurityFunctionsFromIdentity bundles an identity with the entitlement proof
// providers. ProvidePN/ProvideHCV may be nil when only the VAU handshake, authorization
// and /information endpoints are exercised.
func SecurityFunctionsFromIdentity(identity Identity, provideHCV ProvideHCVFunc, providePN ProvidePNFunc) *SecurityFunctions {
	return &SecurityFunctions{
		Identity:   identity,
		ProvidePN:  providePN,
		ProvideHCV: provideHCV,
	}
}

// CommonName is the CN of an RFC 4514 subject DN, or the DN itself without one.
func CommonName(dn string) string {
	for part := range strings.SplitSeq(dn, ",") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return value
		}
	}
	return dn
}
