package main

import (
	"log"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	regBaseURL      = "https://dms-01.zt.dev.ccs.gematik.solutions"
	appIdentityPath = ".app.identity.json"
)
var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "TPM Comands",
}

func init() {
	tpmActivateCmd.Flags().StringVarP(&regBaseURL, "reg-url", "r", regBaseURL, "Registration URL")
	tpmCmd.AddCommand(tpmActivateCmd)
	tpmCmd.AddCommand(tpmIdentity)
	rootCmd.AddCommand(tpmCmd)
}

var tpmActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Activate TPM AK",

	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Activating TPM AK")
		tcl, err := CreateClient(
			regBaseURL,
			appIdentityPath,
		)
		if err != nil {
			log.Fatal(err)
		}
		defer tcl.Close()

		err = tcl.AttestWithServer()
		if err != nil {
			log.Fatal(err)
		}

	},
}

var tpmIdentity = &cobra.Command{
	Use:   "identity",
	Short: "App Identity",
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Loading App Identity")
		tcl, err := CreateClient(
			regBaseURL,
			appIdentityPath,
		)

		if err != nil {
			slog.Error("Error creating client", "error", err)
			os.Exit(1)
		}

		defer tcl.Close()

		slog.Info("App Identity", "identity", tcl.identity)

	},
}
