package oid

import (
	"encoding/asn1"
	"strings"
	"testing"
)

// Every value oid.go declares carries its spec label by construction; this
// pins the size of the tables so a re-generation against a newer
// gemSpec_OID shows up as a deliberate change, and keeps the refs honest.
func TestLabels_MirrorGemSpecOID(t *testing.T) {
	const declared = 210 // Tab_PKI_401–406 of gemSpec_OID V3.25.0, minus the one "tbd" row
	if len(infos) != declared {
		t.Fatalf("%d labelled OIDs, want %d", len(infos), declared)
	}
	refs := map[string]string{}
	for oid, info := range infos {
		if !strings.HasPrefix(info.Ref, "oid_") || strings.ContainsAny(info.Ref, " \t") {
			t.Errorf("%s: ref %q is not a gemSpec_OID reference", oid, info.Ref)
		}
		if info.Description == "" {
			t.Errorf("%s (%s): no description", oid, info.Ref)
		}
		if prev, dup := refs[info.Ref]; dup {
			t.Errorf("ref %s used for both %s and %s", info.Ref, prev, oid)
		}
		refs[info.Ref] = oid
	}
	for _, o := range append(append([]asn1.ObjectIdentifier{}, Professions...), Institutions...) {
		if _, ok := infos[o.String()]; !ok {
			t.Errorf("%s is in a table but has no label", o)
		}
	}
	if info, _ := Lookup(ProfArzt); info.Ref != "oid_arzt" || info.Description != "Ärztin/Arzt" {
		t.Errorf("ProfArzt label = %+v", info)
	}
	if info, _ := Lookup(CertTypeEgkQES); info.Ref != "oid_egk_qes" || info.Document != "[gemSpec_PKI]" {
		t.Errorf("CertTypeEgkQES label = %+v", info)
	}
}
