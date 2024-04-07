package main

import (
	"fmt"
	"log"
	"log/slog"
	"reflect"

	"github.com/google/go-attestation/attest"
	"github.com/spf13/cobra"
)

var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "TPM Comands",
}

func init() {
	tpmCmd.AddCommand(tpmActivateCmd)
	tpmCmd.AddCommand(tpmTestCmd)
	rootCmd.AddCommand(tpmCmd)
}

var tpmActivateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Activate TPM AK",
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Activating TPM AK")
		tcl, err := CreateClient(
			//"http://192.168.1.133:8080",
			"https://dms-01.zt.dev.ccs.gematik.solutions",
			".tpm.ak.id.json",
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

var tpmTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test TPM",
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Testing TPM")

		config := &attest.OpenConfig{}
		tpm, err := attest.OpenTPM(config)
		if err != nil {
			log.Fatal(err)
		}

		eks, err := tpm.EKs()
		if err != nil {
			log.Fatal(fmt.Errorf("reading EKs from TPM: %w", err))
		}

		slog.Info("TPM EKs", "count", len(eks))
		for i, ek := range eks {
			slog.Info("EK", "index", i, "cert", ek.Certificate)
		}

		if len(eks) == 0 {
			log.Fatal("No EKs found")
		}

		ek := eks[0]

		akConfig := &attest.AKConfig{
			Parent: &attest.ParentKeyConfig{
				Algorithm: attest.ECDSA,
				Handle:    0x81000002,
			},
		}
		ak, err := tpm.NewAK(akConfig)
		if err != nil {
			log.Fatal(err)
		}

		akBytes, err := ak.Marshal()
		if err != nil {
			log.Fatal(err)
		}

		slog.Info("Created new AK", "ak", reflect.TypeOf(ak.AttestationParameters().Public), "ek_type", reflect.TypeOf(ek.Public), "ak", string(akBytes))

		ak, err = tpm.LoadAK(akBytes)
		if err != nil {
			log.Fatal(err)
		}
	},
}
