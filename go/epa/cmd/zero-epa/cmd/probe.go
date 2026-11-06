// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/gematik/zero-lab/go/epa"
)

var probeProxy = ""

func init() {
	rootCmd.AddCommand(probeCmd)
	probeCmd.PersistentFlags().StringVarP(&probeProxy, "proxy", "p", "", "Specify the proxy to use")

	probeCmd.AddCommand(probePatientCmd)
}

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Run ePA Client as Probe",
	Run: func(cmd *cobra.Command, _ []string) {
		cobra.CheckErr(cmd.Help())
	},
}

var probePatientCmd = &cobra.Command{
	Use:   "patient <kvnr>",
	Short: "Run ePA Client as Probe for Patient",
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		cobra.CheckErr(runProbe(args[0]))
	},
}

// runProbe walks the Aktensysteme for the record of kvnr until one has it, then opens a session there,
// authorizes, entitles and reads the consent decisions. The Aktensysteme are verified under the ti profile;
// one that is refused is a failure with the profile's reason, never a reachable provider.
func runProbe(kvnr string) error {
	proxyName := probeProxy

	slog.Debug("Starting probe", "kvnr", kvnr, "proxy", proxyName)

	var proxyConfig *epa.ProxyConfig
	var ok bool
	if proxyName != "" {
		if proxyConfig, ok = config.GetProxyConfigByName(proxyName); !ok {
			return fmt.Errorf("proxy not found: %s", proxyName)
		}
	} else if proxyConfig, ok = config.GetDefaultProxyConfig(); !ok {
		return errors.New("no default profile found, please specify a profile")
	}

	runner, err := tiBinary()
	if err != nil {
		return err
	}
	proxyConfig.TI = runner
	if err := proxyConfig.Init(); err != nil {
		return err
	}
	sf := proxyConfig.SecurityFunctions
	authenticator := proxyConfig.Authenticator
	subject := sf.Identity.Subject()

	env := proxyConfig.Env
	trust, err := newTiTrust(env)
	if err != nil {
		return err
	}
	defer trust.Close()

	for _, provider := range epa.AllProviders {
		client, err := epa.NewClient(env, provider, sf, epa.WithTLSConfig(trust.config(env)), epa.WithTimeout(proxyConfig.Timeout),
			proxyConfig.VAUVerification())
		if err != nil {
			slog.Error("Failed to create client", "error", err)
			continue
		}

		recordAvailable, err := client.GetRecordStatus(kvnr)
		if err != nil {
			logFailure("Failed to get record status", err, client.BaseURL)
			client.Close()
			continue
		}
		if !recordAvailable {
			slog.Info("Record not available", "kvnr", kvnr, "base_url", client.BaseURL)
			client.Close()
			continue
		}

		slog.Info("Record available", "kvnr", kvnr, "base_url", client.BaseURL)

		slog.Info("Opening VAU session", "env", env, "provider", provider)
		session, err := client.OpenSession()
		if err != nil {
			logFailure("Failed to open session", err, client.BaseURL)
			client.Close()
			continue
		}
		slog.Info("VAU session opened", "env", env, "provider", provider)

		if err := session.Authorize(authenticator); err != nil {
			logFailure("Failed to authorize", err, client.BaseURL)
			client.Close()
			continue
		}
		slog.Info("Authorized", "env", env, "provider", provider, "subject", subject)

		entitle := func() error {
			auditEvidence, err := sf.ProvidePN(kvnr, time.Now())
			if err != nil {
				return err
			}
			hcv, err := sf.ProvideHCV(kvnr)
			if err != nil {
				return err
			}
			return session.SetEntitlementPN(kvnr, auditEvidence, hcv)
		}
		if err := entitle(); err != nil {
			logFailure("Failed to entitle", err, client.BaseURL)
		} else {
			slog.Info("Entitled", "patient", kvnr, "env", env, "provider", provider, "kvnr", kvnr)
		}

		consent, err := client.GetConsentDecisionInformation(kvnr)
		if err != nil {
			logFailure("Failed to get consent decision information", err, client.BaseURL)
		} else {
			slog.Info("Consent decision information", "consent", consent)
		}

		client.Close()
		break
	}
	return nil
}

// logFailure logs a failed step at an Aktensystem; a TLS failure is told as `ti probe` tells it, "TLS ti:"
// and the reason.
func logFailure(msg string, err error, baseURL string) {
	if reason, ok := tlsFailure(err); ok {
		slog.Error(msg, "base_url", baseURL, "detail", "TLS ti: "+reason)
		return
	}
	slog.Error(msg, "base_url", baseURL, "error", err)
}
