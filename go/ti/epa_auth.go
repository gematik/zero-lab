package main

import (
	"context"
	"fmt"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/spf13/cobra"
)

const (
	authMethodFlag      = "auth-method"
	authMethodEnv       = "TI_EPA_AUTH_METHOD"
	authMethodConnector = "connector"
	authMethodP12       = "p12"
	authMethodDefault   = authMethodConnector
	authCardFlag        = "card"
	authP12FileFlag     = "p12-file"
	authP12AliasFlag    = "p12-alias"
	authP12PasswordFlag = "p12-password"
	authP12AliasDefault = "alias"
)

var (
	authMethod = envFlag{
		name: authMethodFlag, env: authMethodEnv, def: authMethodDefault,
		usage: "auth method: " + authMethodConnector + " or " + authMethodP12,
	}
	authP12File = envFlag{
		name: authP12FileFlag, env: "TI_EPA_P12_FILE",
		usage: "p12 auth: path to PKCS#12 file (required with --" + authMethodFlag + "=" + authMethodP12 + ")",
	}
	authP12Password = envFlag{
		name: authP12PasswordFlag, env: "TI_EPA_P12_PASSWORD", def: "00",
		usage: "p12 auth: password",
	}

	authCardFlagVal     string
	authP12AliasFlagVal string
)

// AuthMethod produces the SecurityFunctions needed by epa.Client. v1 leaves
// ProvidePN/ProvideHCV nil — entitlement is handled elsewhere.
type AuthMethod interface {
	Name() string
	SecurityFunctions(ctx context.Context) (*epa.SecurityFunctions, error)
}

func addAuthMethodFlags(cmd *cobra.Command) {
	authMethod.register(cmd)
	cmd.RegisterFlagCompletionFunc(authMethodFlag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{authMethodConnector, authMethodP12}, cobra.ShellCompDirectiveNoFileComp
	})

	// Connector group
	addConnectorConfigFlag(cmd)
	cmd.Flags().StringVar(&authCardFlagVal, authCardFlag, "",
		"connector auth: card handle or Telematik-ID (defaults to first SMC-B on the connector)")

	// P12 group
	authP12File.register(cmd)
	cmd.Flags().StringVar(&authP12AliasFlagVal, authP12AliasFlag, authP12AliasDefault,
		"p12 auth: friendly name of the cert/key pair to use")
	authP12Password.register(cmd)
}

// resolveAuthMethod applies the discriminator chain (flag → env → default) and
// validates that only the matching group's required flags were set.
func resolveAuthMethod() (string, error) {
	method, _ := authMethod.resolve()
	if method != authMethodConnector && method != authMethodP12 {
		return "", fmt.Errorf("--%s: unknown method %q (want %s or %s)",
			authMethodFlag, method, authMethodConnector, authMethodP12)
	}
	return method, nil
}

// buildAuthMethod resolves the method and builds the matching implementation.
// Validates that flags from the other group weren't accidentally set. The
// cross-group guards check the explicit flag (.val), not the env fallback, so an
// ambient TI_EPA_P12_* in the shell never blocks the connector method.
func buildAuthMethod() (AuthMethod, error) {
	method, err := resolveAuthMethod()
	if err != nil {
		return nil, err
	}
	switch method {
	case authMethodConnector:
		if authP12File.val != "" {
			return nil, fmt.Errorf("--%s is set but --%s=%s; pass --%s=%s or drop the flag",
				authP12FileFlag, authMethodFlag, authMethodConnector, authMethodFlag, authMethodP12)
		}
		return newConnectorAuthMethod()
	case authMethodP12:
		p12File, _ := authP12File.resolve()
		if p12File == "" {
			return nil, fmt.Errorf("--%s is required when --%s=%s (or set %s)", authP12FileFlag, authMethodFlag, authMethodP12, authP12File.env)
		}
		if authCardFlagVal != "" {
			return nil, fmt.Errorf("--%s is set but --%s=%s; pass --%s=%s or drop the flag",
				authCardFlag, authMethodFlag, authMethodP12, authMethodFlag, authMethodConnector)
		}
		password, _ := authP12Password.resolve()
		return newP12AuthMethod(p12File, authP12AliasFlagVal, password), nil
	}
	return nil, fmt.Errorf("unreachable")
}
