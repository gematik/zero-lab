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
	probeCmd.PersistentFlags().StringP("proxy", "p", "", "Specify the proxy to use")
	viper.BindPFlag("proxy", probeCmd.PersistentFlags().Lookup("proxy"))

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

		proxyName := viper.GetString("proxy")

		slog.Debug("Starting probe", "kvnr", kvnr, "proxy", proxyName)

		var proxyConfig *epa.ProxyConfig
		var ok bool
		if proxyName != "" {
			if proxyConfig, ok = config.GetProxyConfigByName(proxyName); !ok {
				slog.Error("Proxy not found", "proxy", proxyName)
				return
			}
		} else if proxyConfig, ok = config.GetDefaultProxyConfig(); !ok {
			slog.Error("No default profile found, please specify a profile")
			return
		}

		err := proxyConfig.Init()
		cobra.CheckErr(err)
		sf := proxyConfig.SecurityFunctions

		cert, err := sf.AuthnCertFunc()
		cobra.CheckErr(err)

		env := proxyConfig.Env
		idpEnv := epa.IDPEnvironment(env)

		authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
			Idp:        gemidp.GetIdpByEnvironment(idpEnv),
			SignerFunc: gemidp.SignWith(sf.AuthnSignFunc, sf.AuthnCertFunc),
		})
		cobra.CheckErr(err)

		for _, provider := range []epa.ProviderNumber{epa.ProviderNumber1, epa.ProviderNumber2} {
			slog.Info("Opening session", "env", env, "provider", provider)
			session, err := epa.OpenSession(env, provider, sf, epa.WithInsecureSkipVerify(), epa.WithTimeout(proxyConfig.Timeout))
			if err != nil {
				slog.Error("Failed to open session", "error", err)
				continue
			}
			slog.Info("VAU session opened", "env", env, "provider", provider)

			if err := session.Authorize(authenticator); err != nil {
				slog.Error("Failed to authorize", "error", err)
				continue
			}

			slog.Info("Authorized", "env", env, "provider", provider, "subject", cert.Subject.String())

			recordAvailable, err := session.GetRecordStatus(kvnr)
			if err != nil {
				slog.Error("Failed to get record status", "error", err, "base_url", session.BaseURL)
				continue
			}

			if !recordAvailable {
				slog.Info("Record not available", "kvnr", kvnr, "base_url", session.BaseURL)
				continue
			}

			slog.Info("Record available", "kvnr", kvnr, "base_url", session.BaseURL)
			if err := session.Entitle(kvnr); err != nil {
				slog.Error("Failed to entitle", "error", err)
			} else {
				slog.Info("Entitled", "patient", kvnr, "env", env, "provider", provider, "kvnr", kvnr)
			}

			consent, err := session.GetConsentDecisionInformation(kvnr)
			if err != nil {
				slog.Error("Failed to get consent decision information", "error", err)
			} else {
				slog.Info("Consent decision information", "consent", consent)
			}
			break
		}
	},
}
