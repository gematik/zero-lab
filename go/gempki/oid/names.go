package oid

import "encoding/asn1"

// Info is what gemSpec_OID records about an object identifier: the
// reference other gematik documents cite it by, a description, and the
// document that defines it.
type Info struct {
	// Ref is the gemSpec_OID reference name, e.g. `oid_policy_gem_or_cp`.
	Ref string
	// Description is the spec's own wording, kept in German where that is
	// how the table reads; for certificate types it is the type name.
	Description string
	// Document is the defining document, e.g. `[gemSpec_TSL]`. Empty when
	// the table names none.
	Document string
	// CertificateTypes lists, for a technical role (Tab_PKI_406), the
	// certificate types whose Admission extension may carry it, e.g.
	// C.FD.AUT. Nil for every other table and for roles no profile uses.
	CertificateTypes []string
}

// infos is keyed by the dotted form so lookup needs no OID comparison. It
// is filled by the def* constructors as oid.go declares each value, so an
// OID cannot exist without its label.
var infos = map[string]Info{}

func defAt(oid asn1.ObjectIdentifier, ref, description string) asn1.ObjectIdentifier {
	return defAtIn(oid, ref, description, "")
}

func defAtIn(oid asn1.ObjectIdentifier, ref, description, document string) asn1.ObjectIdentifier {
	infos[oid.String()] = Info{Ref: ref, Description: description, Document: document}
	return oid
}

// def declares an OID under the gematik arc 1.2.276.0.76.4.
func def(arc int, ref, description string) asn1.ObjectIdentifier {
	return defAt(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, arc}, ref, description)
}

func defIn(arc int, ref, description, document string) asn1.ObjectIdentifier {
	return defAtIn(asn1.ObjectIdentifier{1, 2, 276, 0, 76, 4, arc}, ref, description, document)
}

// defRole declares a Tab_PKI_406 role with the certificate types allowed to
// carry it.
func defRole(arc int, ref, description string, certificateTypes ...string) asn1.ObjectIdentifier {
	oid := def(arc, ref, description)
	info := infos[oid.String()]
	info.CertificateTypes = certificateTypes
	infos[oid.String()] = info
	return oid
}

// Lookup returns what gemSpec_OID says about oid; ok is false for an OID
// this package does not declare.
func Lookup(oid asn1.ObjectIdentifier) (Info, bool) {
	info, ok := infos[oid.String()]
	return info, ok
}

// Format renders an OID for display: `1.2.276.0.76.4.328 (ZETA Guard)`
// when the name is known, the bare dotted form otherwise.
func Format(oid asn1.ObjectIdentifier) string {
	if info, ok := infos[oid.String()]; ok && info.Description != "" {
		return oid.String() + " (" + info.Description + ")"
	}
	return oid.String()
}
