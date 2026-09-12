// Package smcb turns an SMC-B — a software PKCS#12 or a card behind a
// Konnektor — into the one thing every TI login needs from it: a function
// that signs a digest with the C.AUT key and the certificate that goes with
// it. The ePA session, the IDP-Dienst authenticator and anything that comes
// after them consume this shape; the flags that pick the method are shared
// too, so every command spells them the same way.
package smcb

import (
	"crypto/x509"
	"log/slog"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
)

// Identity is a C.AUT signing capability plus its certificate.
type Identity struct {
	Sign brainpool.SignFunc
	Cert func() (*x509.Certificate, error)

	// Source says where the identity came from, for diagnostics: the P12
	// path or the connector card handle.
	Source string
}

// Certificate returns the C.AUT certificate, or nil when it is unavailable.
func (id *Identity) Certificate() *x509.Certificate {
	if id == nil || id.Cert == nil {
		return nil
	}
	cert, err := id.Cert()
	if err != nil {
		slog.Debug("smcb: no auth cert available", "err", err)
		return nil
	}
	return cert
}

// TelematikID is the admission statement's registrationNumber, or "" when
// the certificate carries none — callers label things with it, never gate
// on it.
func (id *Identity) TelematikID() string {
	cert := id.Certificate()
	if cert == nil {
		return ""
	}
	as, err := gempki.ParseAdmissionStatement(cert)
	if err != nil {
		slog.Debug("smcb: parsing admission statement failed", "err", err)
		return ""
	}
	return as.RegistrationNumber
}
