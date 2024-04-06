package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest"
	"github.com/google/go-attestation/attest"
	"github.com/spf13/cobra"
)

var tpmCmd = &cobra.Command{
	Use:   "tpm-activate",
	Short: "Activate the TPM AK",
	//Args:  cobra.MatchAll(cobra.ExactArgs(1)),
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Activating TPM AK")
		tcl, err := CreateClient(".tpm.ak.id.json")
		if err != nil {
			log.Fatal(err)
		}

		err = tcl.ActivateTPM()
		if err != nil {
			log.Fatal(err)
		}

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

func CreateClient(akPath string) (*TrustClient, error) {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return nil, err
	}

	ak, err := loadAK(tpm, akPath)
	if err != nil {
		slog.Info(fmt.Sprintf("%s. Will create new AK.", err))
		akConfig := &attest.AKConfig{}
		ak, err = tpm.NewAK(akConfig)
		if err != nil {
			return nil, err
		}
		err = saveAK(akPath, ak)
		if err != nil {
			return nil, err
		}
	} else {
		slog.Info("Loaded existing AK", "path", akPath)
	}

	return &TrustClient{
		TPM: tpm,
		AK:  ak,
	}, nil
}

func (c *TrustClient) ActivateTPM() error {
	slog.Info("Activating TPM")
	attestParams := c.AK.AttestationParameters()

	attestationRequest, err := tpmattest.CreateAttestationRequest(c.TPM, &attestParams)
	if err != nil {
		return fmt.Errorf("creating attestation request: %w", err)
	}

	httpClient := &http.Client{}

	body, err := json.Marshal(attestationRequest)
	if err != nil {
		return fmt.Errorf("marshaling activation request: %w", err)
	}

	slog.Info("Activation request", "body", string(body))
	resp, err := httpClient.Post("http://192.168.1.133:8080/tpm/activations", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending activation request: %w", err)
	}

	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	slog.Info("Activation response", "status", resp.Status, "body", string(body))

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (c *TrustClient) Close() {
	c.TPM.Close()
}

func saveAK(path string, ak *attest.AK) error {
	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("marshaling AK: %w", err)
	}

	if err := os.WriteFile(path, akBytes, 0600); err != nil {
		return fmt.Errorf("writing AK: %w", err)
	}

	return nil
}

func loadAK(tpm *attest.TPM, path string) (*attest.AK, error) {
	akBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading AK: %w", err)
	}

	ak, err := tpm.LoadAK(akBytes)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}

	return ak, nil
}
