package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"reflect"

	"github.com/gematik/zero-lab/pkg/attestation/tpmattest"
	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/google/go-attestation/attest"
)

type TrustClient struct {
	regBaseURL string
	tpm        *attest.TPM
	identity   *Identity
	ek         *attest.EK
}

func CreateClient(regBaseURL string, identityPath string) (*TrustClient, error) {
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

	if len(eks) == 0 {
		return nil, fmt.Errorf("no EKs found")
	}

	ek := eks[0]
	slog.Info("EK", "public_key", ek.Public)
	if ek.Certificate != nil {
		slog.Info("EK Certificate", "subject", ek.Certificate.Subject.String(), "issuer", ek.Certificate.Issuer.String(), "not_before", ek.Certificate.NotBefore, "not_after", ek.Certificate.NotAfter)
	}

	var identity *Identity
	// check if file exists
	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		slog.Info("Identity file does not exist. Will create new Identity.")
		identity = &Identity{
			tpm: tpm,
		}

		err = identity.save(identityPath)
		if err != nil {
			return nil, err
		}
	} else {
		identity, err = LoadIdentity(tpm, identityPath)
		if err != nil {
			return nil, fmt.Errorf("loading identity from '%s': %w", identityPath, err)
		}
		slog.Info("Identity loaded", "path", identityPath, "identity", identity)

	}

	return &TrustClient{
		regBaseURL: regBaseURL,
		tpm:        tpm,
		identity:   identity,
		ek:         &ek,
	}, nil
}

func (c *TrustClient) ActivateAndCertifyAK() error {
	slog.Info("Activating and certifying AK")
	// create new AK
	ak, err := c.tpm.NewAK(nil)
	if err != nil {
		return err
	}

	puk, err := attest.ParseAKPublic(c.tpm.Version(), ak.AttestationParameters().Public)
	if err != nil {
		return fmt.Errorf("parsing AK public key: %w", err)
	}

	slog.Info("Created new AK", "public_key", puk.Public, "public_key_type", reflect.TypeOf(puk.Public))

	attestParams := ak.AttestationParameters()

	activationRequest, err := tpmattest.NewActivationRequest(c.tpm, *c.ek, &attestParams)
	if err != nil {
		return fmt.Errorf("creating activation request: %w", err)
	}
	slog.Info("Activation request created", "request", activationRequest)

	httpClient := &http.Client{}

	body, err := json.Marshal(activationRequest)
	if err != nil {
		return fmt.Errorf("marshaling activation request: %w", err)
	}

	url := fmt.Sprintf("%s/tpm/activations", c.regBaseURL)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending activation request: %w", err)
	}

	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		slog.Error("Unexpected status code", "status_code", resp.StatusCode, "body", string(body))
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	challenge := new(tpmattest.ActivationChallenge)
	err = json.Unmarshal(body, challenge)
	if err != nil {
		return fmt.Errorf("unmarshaling activation challenge: %w", err)
	}

	slog.Info("Received activation challenge", "challenge", challenge)

	secret, err := ak.ActivateCredential(c.tpm, challenge.EncryptedCredential())
	if err != nil {
		return fmt.Errorf("activating credential: %w", err)
	}

	challengeResponse := &tpmattest.ActivationChallengeResponse{
		DecryptedSecret: secret,
	}

	slog.Info("Sending challenge response", "response", challengeResponse)

	body, err = json.Marshal(challengeResponse)
	if err != nil {
		return fmt.Errorf("marshaling challenge response: %w", err)
	}

	url = fmt.Sprintf("%s/tpm/activations/%s", c.regBaseURL, challenge.ID)
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
		slog.Error("Unexpected status code", "status_code", resp.StatusCode, "body", string(body))
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	verification := new(tpmattest.ChallengeVerificationResponse)
	err = json.Unmarshal(body, verification)
	if err != nil {
		return fmt.Errorf("unmarshaling challenge verification: %w", err)
	}

	slog.Info("Received challenge verification response", "verification", verification)

	if verification.Status != "valid" {
		return fmt.Errorf("challenge failed with status: %s", challenge.Status)
	}

	akCert, err := x509.ParseCertificate(verification.AttestationCertificateRaw)
	if err != nil {
		return fmt.Errorf("parsing AK certificate: %w", err)
	}

	c.identity.DeleteAK()
	c.identity.UpdateAK(ak)
	c.identity.UpdateAKCertificate(akCert)
	c.identity.save(appIdentityPath)

	slog.Info("AK activation and certification successful.")

	return nil
}

func (c *TrustClient) Close() {
	c.tpm.Close()
}

// Creates a certificate signing request (CSR) for the AK.
func (c *TrustClient) createCSR(prk crypto.PrivateKey) ([]byte, *x509.CertificateRequest, error) {
	slog.Info("Creating CSR")
	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Test Certificate"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	// step: generate the csr request
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, prk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create csr request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse csr request: %w", err)
	}
	return csrBytes, csr, nil
}

func (c *TrustClient) RenewClientCertificate() (*x509.Certificate, error) {
	slog.Info("Renewing client certificate")
	ak, err := c.identity.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	newClientKey, err := c.tpm.NewKey(ak, &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
	})
	if err != nil {
		return nil, fmt.Errorf("creating app key: %w", err)
	}

	slog.Info("Created app key", "key_type", reflect.TypeOf(newClientKey.Public()))

	certParams := newClientKey.CertificationParameters()

	akCert, err := c.identity.AKCertificate()
	if err != nil {
		return nil, fmt.Errorf("loading AK certificate: %w", err)
	}

	err = certParams.Verify(attest.VerifyOpts{
		Public: akCert.PublicKey,
		Hash:   crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("verifying AK certificate: %w", err)
	}

	slog.Info("Client key certification parameters", "cert_params", certParams)

	err = c.identity.UpdateClientKey(newClientKey)
	if err != nil {
		return nil, fmt.Errorf("saving identity: %w", err)
	}

	prk, err := c.identity.ClientPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("loading private key: %w", err)
	}

	csrBytes, csr, err := c.createCSR(prk)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}

	slog.Info("CSR", "csr", base64.StdEncoding.EncodeToString(csrBytes))

	mockCA, err := ca.NewRandomMockCA()
	if err != nil {
		return nil, fmt.Errorf("creating mock CA: %w", err)
	}

	cert, err := mockCA.SignCertificateRequest(csr, pkix.Name{CommonName: "Test Certificate"}, ca.WithAdditionalInformation(
		&struct {
			Owner             string `json:"owner"`
			AttestationMethod string `json:"attestation_method"`
		}{
			Owner:             "unregistered",
			AttestationMethod: "tpm",
		},
	))
	if err != nil {
		return nil, fmt.Errorf("signing certificate request: %w", err)
	}

	// save the certificate
	c.identity.UpdateClientCertificate(cert)
	err = c.identity.save(appIdentityPath)
	if err != nil {
		return nil, fmt.Errorf("saving identity: %w", err)
	}

	return cert, nil
}
