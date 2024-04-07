package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"reflect"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest"
	"github.com/google/go-attestation/attest"
)

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

	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("reading EKs from TPM: %w", err)
	}

	slog.Info("TPM EKs", "count", len(eks))
	for i, ek := range eks {
		slog.Info("EK", "index", i, "cert", ek.Certificate)
	}

	if len(eks) == 0 {
		return nil, fmt.Errorf("no EKs found")
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

	slog.Info("Activation request", "request", attestationRequest)
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

	challengeResponse := &tpmattest.AttestationChallengeResponse{
		DecryptedSecret: secret,
	}

	slog.Info("Sending challenge response", "response", challengeResponse)

	body, err = json.Marshal(challengeResponse)
	if err != nil {
		return fmt.Errorf("marshaling challenge response: %w", err)
	}

	url = fmt.Sprintf("%s/tpm/attestations/%s", c.regBaseURL, challenge.ID)
	resp, err = httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending challenge response: %w", err)
	}

	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	err = json.Unmarshal(body, challenge)
	if err != nil {
		return fmt.Errorf("unmarshaling attestation challenge: %w", err)
	}

	slog.Info("Received attestation challenge", "challenge", challenge)

	if challenge.Status != "valid" {
		return fmt.Errorf("challenge failed with status: %s", challenge.Status)
	}

	slog.Info("Attestation successful. Creating app key.")

	appKey, err := c.tpm.NewKey(c.ak, &attest.KeyConfig{
		Algorithm: attest.ECDSA,
	})
	if err != nil {
		return fmt.Errorf("creating app key: %w", err)
	}

	slog.Info("Created app key", "key", appKey)

	return nil
}

func (c *TrustClient) Close() {
	c.tpm.Close()
}

// Creates a certificate signing request (CSR) for the AK.
func (c *TrustClient) CreateCSR() ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Test Certificate"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	slog.Info("csrTemplate", "csrTemplate.extraExtensions", csrTemplate.ExtraExtensions)
	// step: generate the csr request
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, c.ak)
	if err != nil {
		return nil, fmt.Errorf("failed to create csr request: %w", err)
	}
	return csrBytes, nil
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
