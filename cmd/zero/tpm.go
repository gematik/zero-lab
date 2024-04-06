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
	"reflect"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/google/go-attestation/attest"
	"github.com/spf13/cobra"
)

var tpmCmd = &cobra.Command{
	Use:   "tpm-activate",
	Short: "Activate the TPM AK",
	//Args:  cobra.MatchAll(cobra.ExactArgs(1)),
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Activating TPM AK")
		tcl, err := CreateClient("http://192.168.1.133:8080", ".tpm.ak.id.json")
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

func init() {
	rootCmd.AddCommand(tpmCmd)
}

type TrustClient struct {
	regBaseURL string
	tpm        *attest.TPM
	ak         *attest.AK
	ek         *attest.EK
}

func CreateClient(regBaseURL string, akPath string) (*TrustClient, error) {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return nil, err
	}

	eks, err := tpm.EKCertificates()
	if err != nil {
		return nil, fmt.Errorf("reading EKs from TPM: %w", err)
	}

	slog.Info("TPM EKs", "count", len(eks))
	for i, ek := range eks {
		slog.Info("EK", "index", i, "cert", util.CertificateToText(ek.Certificate))
	}

	ek := eks[0]

	ak, err := loadAK(tpm, akPath)
	if err != nil {
		slog.Info(fmt.Sprintf("%s. Will create new AK.", err))
		akConfig := &attest.AKConfig{
			Parent: &attest.ParentKeyConfig{
				Algorithm: attest.ECDSA,
				Handle:    0x81000002,
			},
		}
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

	publicKey, err := attest.ParseAKPublic(tpm.Version(), ak.AttestationParameters().Public)
	if err != nil {
		return nil, fmt.Errorf("parsing AK public key: %w", err)
	}

	slog.Info("AK public key", "type", reflect.TypeOf(publicKey.Public))

	return &TrustClient{
		regBaseURL: regBaseURL,
		tpm:        tpm,
		ak:         ak,
		ek:         &ek,
	}, nil
}

func (c *TrustClient) AttestWithServer() error {
	slog.Info("Activating TPM")
	attestParams := c.ak.AttestationParameters()

	attestationRequest, err := tpmattest.CreateAttestationRequest(c.tpm, *c.ek, &attestParams)
	if err != nil {
		return fmt.Errorf("creating attestation request: %w", err)
	}

	httpClient := &http.Client{}

	body, err := json.Marshal(attestationRequest)
	if err != nil {
		return fmt.Errorf("marshaling activation request: %w", err)
	}

	slog.Info("Activation request", "body", string(body))
	url := fmt.Sprintf("%s/tpm/attestations", c.regBaseURL)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
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

	challenge := new(tpmattest.AttestationChallenge)
	err = json.Unmarshal(body, challenge)
	if err != nil {
		return fmt.Errorf("unmarshaling attestation challenge: %w", err)
	}

	slog.Info("Received attestation challenge", "challenge", challenge)

	secret, err := c.ak.ActivateCredentialWithEK(c.tpm, challenge.EncryptedCredential(), *c.ek)
	if err != nil {
		return fmt.Errorf("activating credential: %w", err)
	}
	slog.Info("Activated AK", "secret", secret)

	return nil
}

func (c *TrustClient) Close() {
	c.tpm.Close()
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
