package gempki

import (
	"testing"

	"github.com/gematik/zero-lab/go/gempki/oid"
)

// The oid package labels the Tab_PKI_405 types by hand; this is what keeps
// its table and certTypePairs from drifting apart.
func TestCertTypes_AreLabelledInOID(t *testing.T) {
	for _, p := range certTypePairs {
		info, ok := oid.Lookup(p.oid)
		if !ok {
			t.Errorf("%s: no oid label for %s", p.t, p.oid)
			continue
		}
		if info.Description != string(p.t) {
			t.Errorf("%s: oid label says %q", p.t, info.Description)
		}
	}
}
