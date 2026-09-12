package epa

import (
	"context"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/ti/internal/smcb"
	"github.com/spf13/cobra"
)

// AuthMethod produces the SecurityFunctions needed by epa.Client from the
// SMC-B identity the shared --auth-* flags select. v1 leaves
// ProvidePN/ProvideHCV nil — entitlement is handled elsewhere.
type AuthMethod interface {
	Name() string
	SecurityFunctions(ctx context.Context) (*epa.SecurityFunctions, error)
}

func addAuthMethodFlags(cmd *cobra.Command) { smcb.AddFlags(cmd) }

func buildAuthMethod() (AuthMethod, error) {
	m, err := smcb.Build()
	if err != nil {
		return nil, err
	}
	return authMethod{m}, nil
}

type authMethod struct{ smcb.Method }

func (a authMethod) SecurityFunctions(ctx context.Context) (*epa.SecurityFunctions, error) {
	id, err := a.Identity(ctx)
	if err != nil {
		return nil, err
	}
	return securityFunctions(id), nil
}

// securityFunctions uses the one C.AUT identity for both authn and the
// client assertion; entitlement providers stay nil.
func securityFunctions(id *smcb.Identity) *epa.SecurityFunctions {
	return &epa.SecurityFunctions{
		AuthnSignFunc:           id.Sign,
		AuthnCertFunc:           id.Cert,
		ClientAssertionSignFunc: id.Sign,
		ClientAssertionCertFunc: id.Cert,
	}
}
