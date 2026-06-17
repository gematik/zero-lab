package gempki

import (
	"crypto/x509"
	"encoding/asn1"
)

// ChainPosition labels a certificate's role in a validated chain.
type ChainPosition string

const (
	// PositionEE — end-entity certificate (the leaf the caller cares about).
	PositionEE ChainPosition = "end_entity"

	// PositionSubCA — intermediate CA between the end-entity and a trusted root.
	PositionSubCA ChainPosition = "sub_ca"

	// PositionRoot — trusted root anchor.
	PositionRoot ChainPosition = "root"
)

// CertResult captures the per-certificate findings the Validator produced
// while walking the chain. Fields that don't apply to a position
// (e.g. RoleOIDs on a root) are left zero-valued.
type CertResult struct {
	Subject     string
	Position    ChainPosition
	Revocation  *RevocationResult // nil if revocation was skipped or not yet checked
	PolicyMatch bool              // required CertificatePolicy assertions matched
	RoleOIDs    []asn1.ObjectIdentifier
	RoleMatch   bool // required role OIDs were found in RoleOIDs
}

// ValidationResult is the outcome of a single [Validator].Validate call.
//
// Valid is true only when every check passed; Errors enumerates the
// problems that caused Valid to be false. Warnings record non-fatal
// observations that did not affect the verdict.
//
// Chain and Positions are parallel slices indexed the same way:
// Chain[i] is positioned at Positions[i] and detailed in CertResults[i].
type ValidationResult struct {
	Valid       bool
	Chain       []*x509.Certificate
	Positions   []ChainPosition
	Errors      []*ValidationError
	Warnings    []*ValidationWarning
	CertResults []CertResult
}

// HasError reports whether the result contains at least one error with the
// given code. Useful for callers that need to discriminate revoked-vs-expired
// without scanning the slice manually.
func (r *ValidationResult) HasError(code ErrorCode) bool {
	if r == nil {
		return false
	}
	for _, e := range r.Errors {
		if e != nil && e.Code == code {
			return true
		}
	}
	return false
}
