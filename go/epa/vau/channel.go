package vau

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

type Env byte

const EnvNonPU Env = 0
const EnvPU Env = 1

const (
	Version        = byte(0x02)
	HeaderRequest  = byte(0x01)
	HeaderResponse = byte(0x02)
)

type Counter struct {
	mu    sync.Mutex
	value uint64
}

func (c *Counter) next() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
	return c.value
}

type Channel struct {
	httpClient          *http.Client
	Env                 Env
	ID                  string
	ChannelURL          *url.URL
	SignedPublicVAUKeys *SignedPublicVAUKeys
	keyID               []byte
	// key and counter for k2_c2s_app_data
	k2_c2s_app_data         []byte
	k2_c2s_app_data_counter Counter
	// key to decrypt the responses from server
	k2_s2c_app_data []byte
	// request/response counter
	requestCounter Counter
}

type EncryptedRequest struct {
	RequestCounter uint64
	Ciphertext     []byte
}

// ChannelSnapshot captures everything needed to resume an open VAU channel from a
// different process. AEAD keys, the channel ID/URL, and both monotonic counters
// are included; the HTTP client and SignedPublicVAUKeys are intentionally
// excluded (the client is process-local, the server keys are only used during
// the initial handshake and are not consulted on subsequent Encrypt/Decrypt).
//
// The receiver of a ChannelSnapshot MUST persist counters at least as often as it
// sends VAU requests — counter reuse breaks AES-GCM nonce uniqueness AND will
// be rejected by the server. The simplest correct pattern: snapshot after each
// successful request, drop the snapshot on any failure, fall back to a fresh
// handshake.
type ChannelSnapshot struct {
	Env                 Env    `json:"env"`
	ID                  string `json:"id"`
	ChannelURL          string `json:"channel_url"`
	KeyID               []byte `json:"key_id"`
	K2C2SAppData        []byte `json:"k2_c2s_app_data"`
	K2C2SAppDataCounter uint64 `json:"k2_c2s_app_data_counter"`
	K2S2CAppData        []byte `json:"k2_s2c_app_data"`
	RequestCounter      uint64 `json:"request_counter"`
}

// Snapshot returns the current state of the channel suitable for persistence.
// Counters are read under their respective locks so concurrent senders don't
// race the snapshotter.
func (c *Channel) Snapshot() ChannelSnapshot {
	c.requestCounter.mu.Lock()
	rc := c.requestCounter.value
	c.requestCounter.mu.Unlock()

	c.k2_c2s_app_data_counter.mu.Lock()
	cc := c.k2_c2s_app_data_counter.value
	c.k2_c2s_app_data_counter.mu.Unlock()

	return ChannelSnapshot{
		Env:                 c.Env,
		ID:                  c.ID,
		ChannelURL:          c.ChannelURL.String(),
		KeyID:               append([]byte(nil), c.keyID...),
		K2C2SAppData:        append([]byte(nil), c.k2_c2s_app_data...),
		K2C2SAppDataCounter: cc,
		K2S2CAppData:        append([]byte(nil), c.k2_s2c_app_data...),
		RequestCounter:      rc,
	}
}

// RestoreChannel reconstructs a Channel from a previously captured state. The
// HTTP client is provided by the caller (typically wired with the same cert
// pool used at handshake time). Subsequent Encrypts will resume from the
// counters in the state.
func RestoreChannel(state ChannelSnapshot, httpClient *http.Client) (*Channel, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("RestoreChannel: httpClient is required")
	}
	u, err := url.Parse(state.ChannelURL)
	if err != nil {
		return nil, fmt.Errorf("RestoreChannel: parsing channel URL: %w", err)
	}
	if len(state.KeyID) == 0 || len(state.K2C2SAppData) == 0 || len(state.K2S2CAppData) == 0 {
		return nil, fmt.Errorf("RestoreChannel: state is missing required key material")
	}
	return &Channel{
		httpClient:              httpClient,
		Env:                     state.Env,
		ID:                      state.ID,
		ChannelURL:              u,
		keyID:                   append([]byte(nil), state.KeyID...),
		k2_c2s_app_data:         append([]byte(nil), state.K2C2SAppData...),
		k2_c2s_app_data_counter: Counter{value: state.K2C2SAppDataCounter},
		k2_s2c_app_data:         append([]byte(nil), state.K2S2CAppData...),
		requestCounter:          Counter{value: state.RequestCounter},
	}, nil
}

func (c *Channel) Do(req *http.Request) (*http.Response, error) {
	encrypted, err := c.EncryptRequest(req)
	if err != nil {
		return nil, fmt.Errorf("encrypting request: %w", err)
	}
	// simulate the race condition by delaying the request randomly
	encResp, err := c.PostEncryptedRequest(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("posting encrypted request: %w", err)
	}

	slog.Debug("Received VAU response", "channel_url", c.ChannelURL.String(), "requestCounter", encrypted.RequestCounter, "status", encResp.StatusCode)

	if encResp.StatusCode != http.StatusOK {
		messageError := new(MessageError)
		body, err := io.ReadAll(encResp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading error response: %w", err)
		}
		if err := cbor.NewDecoder(bytes.NewReader(body)).Decode(messageError); err != nil {
			slog.Error("Decoding error response failed", "error", err, "body", string(body), "http_status", encResp.StatusCode, "header", encResp.Header)
			return nil, fmt.Errorf("decoding error: %w", err)
		}
		return nil, fmt.Errorf("server %s: %w", c.ChannelURL, messageError)
	}

	return c.DecryptResponse(encResp, req)
}

func (c *Channel) EncryptRequest(r *http.Request) (*EncryptedRequest, error) {
	slog.Debug("Encrypting VAU request", "channel_url", c.ChannelURL.String(), "method", r.Method, "url", r.URL.String())
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return nil, fmt.Errorf("dumping request: %w", err)
	}
	slog.Debug("VAU request", "channel_url", c.ChannelURL.String(), "method", r.Method, "url", r.URL.String(), "data", string(data))
	return c.Encrypt(data)
}

func (c *Channel) Encrypt(data []byte) (*EncryptedRequest, error) {
	requestCounter := c.requestCounter.next()
	header := make([]byte, 43)
	header[0] = Version
	header[1] = byte(c.Env)
	header[2] = HeaderRequest

	binary.BigEndian.PutUint64(header[3:], requestCounter)
	copy(header[11:], c.keyID)

	aes, err := aes.NewCipher(c.k2_c2s_app_data)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM: %w", err)
	}

	// prepare iv
	iv := make([]byte, 12)

	// read random bits to have full iv size
	if _, err := io.ReadAtLeast(rand.Reader, iv, 4); err != nil {
		return nil, fmt.Errorf("generating iv: %w", err)
	}
	// add 64 bit from counter
	binary.LittleEndian.PutUint64(iv[4:], c.k2_c2s_app_data_counter.next())

	// encrypt data
	ciphertext := aesGCM.Seal(iv, iv, data, header)

	return &EncryptedRequest{
		RequestCounter: requestCounter,
		Ciphertext:     append(header, ciphertext...),
	}, nil
}

func (c *Channel) DecryptResponse(resp *http.Response, req *http.Request) (*http.Response, error) {
	// read body
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return c.Decrypt(data, req)
}

func (c *Channel) Decrypt(data []byte, req *http.Request) (*http.Response, error) {
	if len(data) < 43 {
		return nil, fmt.Errorf("invalid data length: %d", len(data))
	}
	header := data[:43]
	ciphertext := data[43:]

	if header[0] != Version {
		return nil, fmt.Errorf("invalid version: %d", header[0])
	}
	if header[1] != byte(c.Env) {
		return nil, fmt.Errorf("invalid env: %d", header[1])
	}
	if header[2] != HeaderResponse {
		return nil, fmt.Errorf("invalid header: %d", header[2])
	}

	// check if the keyID is the same
	if string(header[11:43]) != string(c.keyID) {
		return nil, fmt.Errorf("invalid keyID: %s", header[11:43])
	}

	aes, err := aes.NewCipher(c.k2_s2c_app_data)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM: %w", err)
	}

	iv := ciphertext[:12]
	ciphertext = ciphertext[12:]

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(plaintext)), req)
	if err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// pick 8 bytes
	requestCounterBytes := header[3:11]
	requestCounter := binary.BigEndian.Uint64(requestCounterBytes)

	slog.Debug("Decrypted VAU response", "channel_url", c.ChannelURL.String(), "server_request_counter", requestCounter, "status_code", resp.StatusCode)

	return resp, nil
}

// PostEncryptedRequest sends previously encrypted data to the server, returning the raw "outer" response.
func (c *Channel) PostEncryptedRequest(data []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.ChannelURL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	return resp, nil
}

type Status struct {
	VAUType            string `json:"VAU-Type"`
	VAUVersion         string `json:"VAU-Version"`
	UserAuthentication string `json:"User-Authentication"`
	KeyID              string `json:"KeyID"`
	ConnectionStart    string `json:"Connection-Start"`
}
