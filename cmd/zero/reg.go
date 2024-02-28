package main

import (
	"log"
	"log/slog"

	"github.com/gematik/zero-lab/pkg/tcl"
	"github.com/spf13/cobra"
)

var regCmd = &cobra.Command{
	Use:   "reg",
	Short: "Register client instance",
	//Args:  cobra.MatchAll(cobra.ExactArgs(1)),
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Registering client")
		idpath := ".client.id.json"
		trustClient, err := tcl.NewSoftwareClient("Generic Software Client", "http://localhost:8080/reg", idpath)
		if err != nil {
			log.Fatal(err)
		}
		slog.Info("Created new trust client", "RegURL", trustClient.RegURL)
		regResp, err := trustClient.CreateRegistration()
		if err != nil {
			log.Fatal(err)
		}
		slog.Info("Got registration response", "id", regResp.ID, "status", regResp.Status, "challenges", regResp.Challenges[0])

		regResp, err = trustClient.GetRegistration()
		if err != nil {
			log.Fatal(err)
		}
		slog.Info("Got registration response", "id", regResp.ID, "status", regResp.Status)

	},
}

func init() {
	rootCmd.AddCommand(regCmd)
}
