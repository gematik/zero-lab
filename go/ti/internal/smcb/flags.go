package smcb

import (
	"context"
	"fmt"

	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

const (
	MethodFlag      = "auth-method"
	MethodConnector = "connector"
	MethodP12       = "p12"
	CardFlag        = "auth-card"
	P12FileFlag     = "auth-p12-file"
	P12AliasFlag    = "auth-p12-alias"
	P12PasswordFlag = "auth-p12-password"
	DefaultAlias    = "alias"
)

var (
	method = common.EnvFlag{
		Name: MethodFlag, Env: "TI_AUTH_METHOD", Def: MethodConnector,
		Usage: "auth method: " + MethodConnector + " or " + MethodP12,
	}
	p12File = common.EnvFlag{
		Name: P12FileFlag, Env: "TI_AUTH_P12_FILE",
		Usage: "p12 auth: path to PKCS#12 file (required with --" + MethodFlag + "=" + MethodP12 + ")",
	}
	p12Password = common.EnvFlag{
		Name: P12PasswordFlag, Env: "TI_AUTH_P12_PASSWORD", Def: "00",
		Usage: "p12 auth: password",
	}

	cardFlagVal     string
	p12AliasFlagVal string
)

// Method is one way of obtaining an Identity, chosen by the shared flags.
type Method interface {
	Name() string
	Identity(ctx context.Context) (*Identity, error)
}

// AddFlags attaches the auth-method flags to a leaf command. They are never
// persistent: only commands that sign take them.
func AddFlags(cmd *cobra.Command) {
	method.Register(cmd)
	cmd.RegisterFlagCompletionFunc(MethodFlag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{MethodConnector, MethodP12}, cobra.ShellCompDirectiveNoFileComp
	})

	// Connector group
	common.AddConnectorConfigFlag(cmd)
	cmd.Flags().StringVar(&cardFlagVal, CardFlag, "",
		"connector auth: SMC-B Telematik-ID, ICCSN, or card handle (defaults to first SMC-B on the connector)")

	// P12 group
	p12File.Register(cmd)
	cmd.Flags().StringVar(&p12AliasFlagVal, P12AliasFlag, DefaultAlias,
		"p12 auth: friendly name of the cert/key pair to use")
	p12Password.Register(cmd)
}

// Build resolves the method (flag → env → default) and checks that only the
// matching group's flags were set. The cross-group guards look at the explicit
// flag value, not the env fallback, so an ambient TI_AUTH_P12_* in the shell
// never blocks the connector method.
func Build() (Method, error) {
	name, _ := method.Resolve()
	switch name {
	case MethodConnector:
		if p12File.Val != "" {
			return nil, fmt.Errorf("--%s is set but --%s=%s; pass --%s=%s or drop the flag",
				P12FileFlag, MethodFlag, MethodConnector, MethodFlag, MethodP12)
		}
		return connectorMethod{cardIdentifier: cardFlagVal}, nil
	case MethodP12:
		path, _ := p12File.Resolve()
		if path == "" {
			return nil, fmt.Errorf("--%s is required when --%s=%s (or set %s)", P12FileFlag, MethodFlag, MethodP12, p12File.Env)
		}
		if cardFlagVal != "" {
			return nil, fmt.Errorf("--%s is set but --%s=%s; pass --%s=%s or drop the flag",
				CardFlag, MethodFlag, MethodP12, MethodFlag, MethodConnector)
		}
		password, _ := p12Password.Resolve()
		return p12Method{path: path, alias: p12AliasFlagVal, password: password}, nil
	}
	return nil, fmt.Errorf("--%s: unknown method %q (want %s or %s)", MethodFlag, name, MethodConnector, MethodP12)
}

type p12Method struct{ path, alias, password string }

func (p p12Method) Name() string { return MethodP12 }
func (p p12Method) Identity(context.Context) (*Identity, error) {
	return FromP12(p.path, p.alias, p.password)
}

type connectorMethod struct{ cardIdentifier string }

func (c connectorMethod) Name() string { return MethodConnector }
func (c connectorMethod) Identity(ctx context.Context) (*Identity, error) {
	return FromConnector(ctx, c.cardIdentifier)
}
