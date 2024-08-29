package authzserver

import (
	"testing"

	"github.com/gematik/zero-lab/go/libzero/oidc"
	"github.com/gematik/zero-lab/go/libzero/util"
)

func CreateTestAuthzServer() (*Server, error) {
	return New(&Config{})
}

func TestAccessToken(t *testing.T) {
	s, err := CreateTestAuthzServer()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	accessToken, err := s.issueAccessToken(&AuthzServerSession{
		ClientID: "test_client",
		Scope:    "test",
		AuthnClientSession: &oidc.AuthnClientSession{
			Claims: map[string]interface{}{
				"sub": "test_identity",
			},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("access token: %s", accessToken)
	t.Log(util.JWSToText(accessToken))
}
