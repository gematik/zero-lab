package tcl

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	regapi "github.com/gematik/zero-lab/pkg/reg/api"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/matishsiao/goInfo"
)

type SoftwareClient struct {
	Name                   string
	RegURL                 string
	httpClient             http.Client
	idpath                 string
	identity               *Identity
	pendingRegistrationURL string
}

func NewSoftwareClient(name string, regBaseURL string, idpath string) (*SoftwareClient, error) {
	identity, err := loadOrCreateIdentityFile(idpath)
	if err != nil {
		return nil, fmt.Errorf("could not load or create identity file: %w", err)
	}
	return &SoftwareClient{
		Name:       name,
		RegURL:     regBaseURL,
		httpClient: http.Client{},
		idpath:     idpath,
		identity:   identity,
	}, nil
}

type SoftwareClientPosture struct {
	OS        string `json:"os"`
	OSVersion string `json:"osVersion"`
	Arch      string `json:"arch"`
}

type RegistrationRequest struct {
	Name     string      `json:"name"`
	Platform string      `json:"platform"`
	Posture  interface{} `json:"posture"`
	Csr      []byte      `json:"csr"`
}

func (c *SoftwareClient) CreateRegistration() (*regapi.RegistrationResponse, error) {
	var err error
	// create new identity
	c.identity, err = newIdentityFile(c.idpath)
	if err != nil {
		return nil, fmt.Errorf("could not create new identity: %w", err)
	}
	nonce, err := c.GetNonce()
	if err != nil {
		return nil, fmt.Errorf("could not get nonce: %w", err)
	}

	gi, err := goInfo.GetInfo()
	slog.Info("Got system info", "info", gi)
	if err != nil {
		return nil, fmt.Errorf("could not get system info: %w", err)
	}
	csr, err := c.createCSR()
	if err != nil {
		return nil, fmt.Errorf("could not create CSR: %w", err)
	}
	regRequest := &RegistrationRequest{
		Name:     c.Name,
		Platform: "software",
		Posture: &SoftwareClientPosture{
			OS:        gi.GoOS,
			OSVersion: gi.Core,
			Arch:      gi.Platform,
		},
		Csr: csr,
	}

	regRequestBytes, err := json.Marshal(regRequest)
	if err != nil {
		return nil, fmt.Errorf("could not marshal registration request: %w", err)
	}

	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, jwa.ES256)
	headers.Set(jws.JWKKey, c.identity.ClientPuK.Key)
	headers.Set(jws.AlgorithmKey, jwa.ES256)
	headers.Set("nonce", nonce)

	message, err := jws.Sign(regRequestBytes, jws.WithKey(jwa.ES256, c.identity.ClientPrK.Key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("could not sign registration request: %w", err)
	}

	slog.Info("Sending registration request", "url", c.RegURL, "registrationRequest", string(regRequestBytes), "message", string(message))

	params := url.Values{}
	params.Add("message", string(message))
	params.Add("attestation_format", "none")

	req, err := http.NewRequest("POST", c.RegURL+"/registrations", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("could not send registration request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected response: %d, %s", resp.StatusCode, string(body))
	}

	c.pendingRegistrationURL = resp.Header.Get("Location")
	slog.Info("Got registration URL", "url", c.pendingRegistrationURL)

	var regResp *regapi.RegistrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	if err != nil {
		return nil, fmt.Errorf("could not decode registration response: %w", err)
	}

	return regResp, nil
}

func (c *SoftwareClient) GetNonce() (string, error) {
	req, err := http.NewRequest("HEAD", c.RegURL+"/nonce", nil)
	if err != nil {
		return "", fmt.Errorf("could not create nonce request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not send nonce request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected response: %d, %s", resp.StatusCode, string(body))
	}

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", fmt.Errorf("no nonce in response")
	}
	slog.Info("Got nonce", "nonce", nonce)
	return nonce, nil
}

func (c *SoftwareClient) createCSR() ([]byte, error) {
	// create certificate signing request
	// step: generate a csr template
	var csrTemplate = x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: c.Name},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, c.identity.MtlsPrK)

	if err != nil {
		return nil, fmt.Errorf("could not create certificate signing request: %w", err)
	}

	return csrCertificate, nil
}

func (c *SoftwareClient) GetRegistration() (*regapi.RegistrationResponse, error) {
	nonce, err := c.GetNonce()
	if err != nil {
		return nil, fmt.Errorf("could not get nonce: %w", err)
	}

	headers := jws.NewHeaders()
	headers.Set(jws.AlgorithmKey, jwa.ES256)
	headers.Set(jws.JWKKey, c.identity.ClientPuK.Key)
	headers.Set(jws.AlgorithmKey, jwa.ES256)
	headers.Set("nonce", nonce)

	message, err := jws.Sign([]byte{}, jws.WithKey(jwa.ES256, c.identity.ClientPrK.Key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("could not sign registration request: %w", err)
	}

	params := url.Values{}
	params.Add("message", string(message))
	params.Add("attestation_format", "none")

	req, err := http.NewRequest("POST", c.pendingRegistrationURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("could not create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send registration request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected response: %d, %s", resp.StatusCode, string(body))
	}

	var regResp *regapi.RegistrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	if err != nil {
		return nil, fmt.Errorf("could not decode registration response: %w", err)
	}

	return regResp, nil
}
