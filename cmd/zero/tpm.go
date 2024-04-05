package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest/tpmtypes"
	"github.com/google/go-attestation/attest"
	"github.com/spf13/cobra"
)

var tpmCmd = &cobra.Command{
	Use:   "tpm-activate",
	Short: "Activate the TPM AK",
	//Args:  cobra.MatchAll(cobra.ExactArgs(1)),
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Activating TPM AK")
		tcl, err := NewUnregisteredClient()
		if err != nil {
			log.Fatal(err)
		}

		tcl.ActivateTPM()

		/*
			akBytes, err := ak.Marshal()
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile("tpm-ak.id.json", akBytes, 0600); err != nil {
				log.Fatal(err)
			}
		*/

	},
}

func init() {
	rootCmd.AddCommand(tpmCmd)
}

type TrustClient struct {
	TPM *attest.TPM
	EK  *attest.EK
	AK  *attest.AK
}

func NewUnregisteredClient() (*TrustClient, error) {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return nil, err
	}

	eks, err := tpm.EKs()
	if err != nil {
		return nil, err
	}

	for _, ek := range eks {
		slog.Info("Endorsement Key", "EK", tpmtypes.NewEK(ek).String())
	}

	return nil, fmt.Errorf("not implemented")

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return nil, err
	}

	return &TrustClient{
		TPM: tpm,
		AK:  ak,
	}, nil
}

func (c *TrustClient) ActivateTPM() error {
	attestParams := c.AK.AttestationParameters()

	tpmEKS, err := c.TPM.EKs()
	if err != nil {
		return fmt.Errorf("getting EKs: %w", err)
	}

	eks := make([]tpmtypes.EK, len(tpmEKS))
	for ind, tpmEK := range tpmEKS {
		eks[ind] = tpmtypes.NewEK(tpmEK)
		slog.Info("Endorsement Key", "EK", eks[ind].String())
	}

	activationRequest := &tpmtypes.ActivationRequest{
		TPMVersion: int(c.TPM.Version()),
		EKs:        eks,
		AK:         tpmtypes.NewAttestationParameters(attestParams),
	}

	httpClient := &http.Client{}

	body, err := json.Marshal(activationRequest)
	if err != nil {
		return fmt.Errorf("marshaling activation request: %w", err)
	}

	resp, err := httpClient.Post("http://192.168.1.133:8080/tmp/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending activation request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	slog.Info("Activation response", "body", string(body))

	slog.Info("Created activation request", "TPMVersion", activationRequest.TPMVersion, "EK.Certificate", c.EK.Certificate.Issuer)
	// send activationRequest to the Trust

	return nil
}
