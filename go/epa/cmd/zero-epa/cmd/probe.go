package cmd

import (
	"log/slog"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(probeCmd)
	probeCmd.AddCommand(probePatientCmd)
}

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Run ePA Client as Probe",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var probePatientCmd = &cobra.Command{
	Use:   "patient <kvnr>",
	Short: "Run ePA Client as Probe for Patient",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		kvnr := args[0]
		sf := createSecurityFunctions()
		env, err := epa.EnvFromString(viper.GetString("env"))
		if err != nil {
			slog.Error("Failed to parse environment", "error", err)
			return
		}

		timeout := viper.GetDuration("timeout")

		cert, err := sf.AuthnCertFunc()
		if err != nil {
			slog.Error("Failed to get authn certificate", "error", err)
			return
		}

		authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
			Environment: epa.IDPEnvironment(env),
			SignerFunc:  gemidp.SignWith(sf.AuthnSignFunc, sf.AuthnCertFunc),
		})

		for _, provider := range []epa.ProviderNumber{epa.ProviderNumber1, epa.ProviderNumber2} {
			slog.Info("Opening session", "env", env, "provider", provider)
			session, err := epa.OpenSession(env, provider, sf, epa.WithInsecureSkipVerify(), epa.WithTimeout(timeout))
			if err != nil {
				slog.Error("Failed to open session", "error", err, "timeout", timeout)
				continue
			}
			slog.Info("VAU session opened", "env", env, "provider", provider)

			if err := session.Authorize(authenticator); err != nil {
				slog.Error("Failed to authorize", "error", err)
				continue
			}

			slog.Info("Authorized", "env", env, "provider", provider, "subject", cert.Subject.String())

			if err := session.Entitle(kvnr); err != nil {
				slog.Error("Failed to entitle", "error", err)
				continue
			}
			slog.Info("Entitled", "env", env, "provider", provider, "kvnr", kvnr)
		}
	},
}

func probe() error {
	return nil
}
