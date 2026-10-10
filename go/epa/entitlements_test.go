package epa_test

import (
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/epatest"
)

// offlineSession builds a Session without an open VAU channel — the tests
// below only exercise the guard paths that must fail before any network I/O.
func offlineSession(t *testing.T, sf *epa.SecurityFunctions) *epa.Session {
	t.Helper()
	client, err := epa.NewClient(epa.EnvDev, epa.ProviderNumber1, sf)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &epa.Session{Client: client}
}

func TestSetEntitlementPN_NoIdentity(t *testing.T) {
	session := offlineSession(t, &epa.SecurityFunctions{})

	err := session.SetEntitlementPN("X110600196", "audit-evidence", []byte{0x01})
	if err == nil {
		t.Fatal("expected error without SMC-B authn identity")
	}
	if !strings.Contains(err.Error(), "no SMC-B authn identity configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetEntitlementPN_NoVAUChannel(t *testing.T) {
	sf := &epa.SecurityFunctions{Identity: &epatest.Identity{SubjectDN: "CN=Test"}}
	session := offlineSession(t, sf)

	err := session.SetEntitlementPN("X110600196", "audit-evidence", []byte{0x01})
	if err == nil {
		t.Fatal("expected error without an open VAU channel")
	}
	if !strings.Contains(err.Error(), "no open VAU channel") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetEntitlementPoPP_NoVAUChannel(t *testing.T) {
	session := offlineSession(t, &epa.SecurityFunctions{})

	_, err := session.SetEntitlementPoPP("X110600196", "some.popp.token")
	if err == nil {
		t.Fatal("expected error without an open VAU channel")
	}
	if !strings.Contains(err.Error(), "no open VAU channel") {
		t.Fatalf("unexpected error: %v", err)
	}
}
