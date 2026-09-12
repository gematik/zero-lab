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
	const declared = 209 // Tab_PKI_401–406 of gemSpec_OID V3.25.0 with C_12646, minus the one "tbd" row
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
	// C_12646: ZETA Guard is a C.FD.AUT / C.FD.TLS-C role, the OCI image
	// role was renamed and the provisioning approver withdrawn.
	if info, _ := Lookup(TechRoleZETAGuard); strings.Join(info.CertificateTypes, " ") != "C.FD.AUT C.FD.TLS-C" {
		t.Errorf("TechRoleZETAGuard types = %v", info.CertificateTypes)
	}
	if info, _ := Lookup(TechRoleZETAOCI); info.Description != "OCI container image für ZETA" {
		t.Errorf("TechRoleZETAOCI = %+v", info)
	}
	if _, ok := infos["1.2.276.0.76.4.332"]; ok {
		t.Error("oid_zeta-prv-approv (332) was withdrawn by C_12646")
	}
}
