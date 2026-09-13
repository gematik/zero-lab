package gempki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"
)

// KeyStatus is what gemSpec_Krypt says about the public key of an
// end-entity certificate.
type KeyStatus int

const (
	// KeyAdmissible is a key the current tables list without reservation.
	KeyAdmissible KeyStatus = iota
	// KeyPhasedOut is a key the tables once listed whose "zulässig bis"
	// date has passed. gemSpec_Krypt enforces that date by removing the
	// issuing CAs from the TSL and tells verifiers not to (A_23458), so a
	// Validator reports it as a warning, never as an error.
	KeyPhasedOut
	// KeyNotAdmissible is a key no table ever listed for a TI
	// certificate. No TSP issues such a certificate; a Validator rejects
	// it.
	KeyNotAdmissible
)

func (s KeyStatus) String() string {
	switch s {
	case KeyAdmissible:
		return "admissible"
	case KeyPhasedOut:
		return "phased out"
	case KeyNotAdmissible:
		return "not admissible"
	}
	return fmt.Sprintf("KeyStatus(%d)", int(s))
}

// rsa2048AdmissibleUntil is the "zulässig bis Ende 2025" of Tab_KRYPT_002.
// Tab_KRYPT_003 (QES) defers to SOG-IS instead, which retires RSA-2048 on
// the same horizon, so one date serves both.
var rsa2048AdmissibleUntil = time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

// ClassifyKey applies gemSpec_Krypt Tab_KRYPT_002/002a (non-QES) and
// Tab_KRYPT_003/003a (QES) to an end-entity public key as of the given
// time, and describes the key for messages ("ECDSA brainpoolP256r1",
// "RSA 2048").
//
// The tables admit ECDSA on brainpoolP256r1 or P-256 and RSA with 2048
// bit, the latter until end of 2025. The spec's own enforcement text
// draws the line at 3000 bit, so longer RSA keys are admissible without a
// date. Everything else — other curves, shorter RSA, non-ECDSA/RSA
// keys — never appeared in a table.
func ClassifyKey(pub crypto.PublicKey, at time.Time) (KeyStatus, string) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil || k.Curve.Params() == nil {
			return KeyNotAdmissible, "ECDSA (unknown curve)"
		}
		name := k.Curve.Params().Name
		desc := "ECDSA " + name
		switch name {
		case "brainpoolP256r1", "P-256":
			return KeyAdmissible, desc
		}
		return KeyNotAdmissible, desc
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return KeyNotAdmissible, "RSA (no modulus)"
		}
		bits := k.N.BitLen()
		desc := fmt.Sprintf("RSA %d", bits)
		switch {
		case bits < 2048:
			return KeyNotAdmissible, desc
		case bits < 3000:
			if at.After(rsa2048AdmissibleUntil) {
				return KeyPhasedOut, desc
			}
			return KeyAdmissible, desc
		}
		return KeyAdmissible, desc
	case nil:
		return KeyNotAdmissible, "no public key"
	}
	return KeyNotAdmissible, fmt.Sprintf("%T", pub)
}
