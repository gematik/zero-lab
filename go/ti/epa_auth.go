package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/spf13/cobra"
)

const (
	authMethodFlag         = "auth-method"
	authMethodEnv          = "TI_EPA_AUTH_METHOD"
	authMethodConnector    = "connector"
	authMethodP12          = "p12"
	authMethodDefault      = authMethodConnector
	authCardFlag           = "card"
	authP12FileFlag        = "p12-file"
	authP12AliasFlag       = "p12-alias"
	authP12PasswordFlag    = "p12-password"
	authP12AliasDefault    = "alias"
	authP12PasswordDefault = "00"
	authP12PasswordEnv     = "TI_EPA_P12_PASSWORD"
)

var (
	authMethodFlagVal      string
	authCardFlagVal        string
	authP12FileFlagVal     string
	authP12AliasFlagVal    string
	authP12PasswordFlagVal string
)

// AuthMethod produces the SecurityFunctions needed by epa.Client. v1 leaves
// ProvidePN/ProvideHCV nil — entitlement is handled elsewhere.
type AuthMethod interface {
	Name() string
	SecurityFunctions(ctx context.Context) (*epa.SecurityFunctions, error)
}

func addAuthMethodFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&authMethodFlagVal, authMethodFlag, "",
		"auth method: "+authMethodConnector+" or "+authMethodP12+" (env: "+authMethodEnv+", default "+authMethodDefault+")")
	cmd.RegisterFlagCompletionFunc(authMethodFlag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{authMethodConnector, authMethodP12}, cobra.ShellCompDirectiveNoFileComp
	})

	// Connector group
	addConnectorConfigFlag(cmd)
	cmd.Flags().StringVar(&authCardFlagVal, authCardFlag, "",
		"connector auth: card handle or Telematik-ID (defaults to first SMC-B on the connector)")

	// P12 group
	cmd.Flags().StringVar(&authP12FileFlagVal, authP12FileFlag, "",
		"p12 auth: path to PKCS#12 file (required with --"+authMethodFlag+"="+authMethodP12+")")
	cmd.Flags().StringVar(&authP12AliasFlagVal, authP12AliasFlag, authP12AliasDefault,
		"p12 auth: friendly name of the cert/key pair to use")
	cmd.Flags().StringVar(&authP12PasswordFlagVal, authP12PasswordFlag, "",
		"p12 auth: password (env: "+authP12PasswordEnv+", default \""+authP12PasswordDefault+"\")")
}

// resolveAuthMethod applies the discriminator chain (flag → env → default) and
// validates that only the matching group's required flags were set.
func resolveAuthMethod() (string, error) {
	method := authMethodFlagVal
	if method == "" {
		method = os.Getenv(authMethodEnv)
	}
	if method == "" {
		method = authMethodDefault
	}
	if method != authMethodConnector && method != authMethodP12 {
		return "", fmt.Errorf("--%s: unknown method %q (want %s or %s)",
			authMethodFlag, method, authMethodConnector, authMethodP12)
	}
	return method, nil
}

// buildAuthMethod resolves the method and builds the matching implementation.
// Validates that flags from the other group weren't accidentally set.
func buildAuthMethod() (AuthMethod, error) {
	method, err := resolveAuthMethod()
	if err != nil {
		return nil, err
	}
	switch method {
	case authMethodConnector:
		if authP12FileFlagVal != "" {
			return nil, fmt.Errorf("--%s is set but --%s=%s; pass --%s=%s or drop the flag",
				authP12FileFlag, authMethodFlag, authMethodConnector, authMethodFlag, authMethodP12)
		}
		return newConnectorAuthMethod()
	case authMethodP12:
		if authP12FileFlagVal == "" {
			return nil, fmt.Errorf("--%s is required when --%s=%s", authP12FileFlag, authMethodFlag, authMethodP12)
		}
		if authCardFlagVal != "" {
			return nil, fmt.Errorf("--%s is set but --%s=%s; pass --%s=%s or drop the flag",
				authCardFlag, authMethodFlag, authMethodP12, authMethodFlag, authMethodConnector)
		}
		return newP12AuthMethod(authP12FileFlagVal, authP12AliasFlagVal, resolveP12Password()), nil
	}
	return nil, fmt.Errorf("unreachable")
}

func resolveP12Password() string {
	if authP12PasswordFlagVal != "" {
		return authP12PasswordFlagVal
	}
	if env := os.Getenv(authP12PasswordEnv); env != "" {
		return env
	}
	return authP12PasswordDefault
}
