package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

type Identity struct {
	FormatVersion string `json:"format_version"`
	tpm           *attest.TPM
	ak            *attest.AK
	key           *attest.Key
	cert          *x509.Certificate
}

func (i *Identity) MarshalJSON() ([]byte, error) {
	var (
		err       error
		sealedAK  []byte
		sealedKey []byte
		certRaw   []byte
	)

	if i.ak != nil {
		sealedAK, err = i.ak.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshaling AK: %w", err)
		}
	}

	if i.key != nil {
		sealedKey, err = i.key.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshaling key: %w", err)
		}
	}

	if i.cert != nil {
		certRaw = i.cert.Raw
	}

	return json.Marshal(map[string]interface{}{
		"format_version": "1",
		"sealed_ak":      sealedAK,
		"sealed_key":     sealedKey,
		"cert_raw":       certRaw,
	})
}

func (i *Identity) UnmarshalJSON(data []byte) error {
	var raw struct {
		FormatVersion string `json:"format_version"`
		SealedAK      []byte `json:"sealed_ak"`
		SealedKey     []byte `json:"sealed_key"`
		CertRaw       []byte `json:"cert_raw"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("unmarshaling identity: %w", err)
	}

	if raw.FormatVersion != "1" {
		return fmt.Errorf("unsupported format version: %s", raw.FormatVersion)
	}

	if len(raw.SealedAK) > 0 {
		ak, err := i.tpm.LoadAK(raw.SealedAK)
		if err != nil {
			return fmt.Errorf("unmarshaling AK: %w", err)
		}
		i.ak = ak
	}

	if len(raw.SealedKey) > 0 {
		key, err := i.tpm.LoadKey(raw.SealedKey)
		if err != nil {
			return fmt.Errorf("unmarshaling key: %w", err)
		}
		i.key = key
	}

	if len(raw.CertRaw) > 0 {
		cert, err := x509.ParseCertificate(raw.CertRaw)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}
		i.cert = cert
	}

	return nil
}

func (i *Identity) PrivateKey() (crypto.PrivateKey, error) {
	if i.key == nil {
		return nil, fmt.Errorf("no key available")
	}

	return i.key.Private(i.key.Public())
}

func saveIdentity(identity *Identity, path string) error {
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("marshaling identity: %w", err)
	}

	if err := os.WriteFile(path, identityBytes, 0600); err != nil {
		return fmt.Errorf("writing AK: %w", err)
	}

	return nil
}

func loadIdentity(tpm *attest.TPM, path string) (*Identity, error) {
	identityBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading AK: %w", err)
	}

	identity := Identity{
		tpm: tpm,
	}

	if err := json.Unmarshal(identityBytes, &identity); err != nil {
		return nil, fmt.Errorf("unmarshaling identity: %w", err)
	}

	return &identity, nil
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

	identity, err := loadIdentity(tpm, identityPath)
	if err != nil {
		slog.Info(fmt.Sprintf("%s. Will create new Identity.", err))
		identity = &Identity{
			tpm: tpm,
		}
		ak, err := tpm.NewAK(nil)
		if err != nil {
			return nil, err
		}
		identity.ak = ak

		err = saveIdentity(identity, identityPath)
		if err != nil {
			return nil, err
		}
	} else {
		slog.Info("Loaded existing identity", "path", identityPath)
	}

	puk, err := attest.ParseAKPublic(tpm.Version(), identity.ak.AttestationParameters().Public)
	if err != nil {
		return nil, fmt.Errorf("parsing AK public key: %w", err)
	}

	slog.Info("AK", "public_key", puk.Public)

	return &TrustClient{
		regBaseURL: regBaseURL,
		tpm:        tpm,
		identity:   identity,
		ek:         &ek,
	}, nil
}

func (c *TrustClient) AttestWithServer() error {
	slog.Info("Activating TPM")
	attestParams := c.identity.ak.AttestationParameters()

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

	secret, err := c.identity.ak.ActivateCredential(c.tpm, challenge.EncryptedCredential())
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

	appKey, err := c.tpm.NewKey(c.identity.ak, &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
	})
	if err != nil {
		return fmt.Errorf("creating app key: %w", err)
	}

	slog.Info("Created app key", "key_type", reflect.TypeOf(appKey.Public()))

	c.identity.key = appKey
	err = saveIdentity(c.identity, appIdentityPath)
	if err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}

	csr, err := c.CreateCSR()
	if err != nil {
		return fmt.Errorf("creating CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	slog.Info("Created CSR", "csr", csrPEM)

	return nil
}

func (c *TrustClient) Close() {
	if c.identity != nil && c.identity.ak != nil {
		c.identity.ak.Close(c.tpm)
	}
	if c.identity != nil && c.identity.key != nil {
		c.identity.key.Close()
	}
	c.tpm.Close()
}

// Creates a certificate signing request (CSR) for the AK.
func (c *TrustClient) CreateCSR() ([]byte, error) {
	prk, err := c.identity.PrivateKey()
	if err != nil {
		return nil, fmt.Errorf("getting private key: %w", err)
	}
	slog.Info("Creating CSR", "public_key", c.identity.key.Public())
	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Test Certificate"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	// step: generate the csr request
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, prk)
	if err != nil {
		return nil, fmt.Errorf("failed to create csr request: %w", err)
	}
	return csrBytes, nil
}

func (c *TrustClient) RenewClientCertificate() (*x509.Certificate, error) {
	csrBytes, err := c.CreateCSR()
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}

	slog.Info("CSR", "csr", base64.StdEncoding.EncodeToString(csrBytes))

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}

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

	c.identity.cert = cert

	err = saveIdentity(c.identity, appIdentityPath)
	if err != nil {
		return nil, fmt.Errorf("saving identity: %w", err)
	}

	return cert, nil
}
