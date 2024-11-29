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
	HostURL             *url.URL
	SignedPublicVAUKeys *SignedPublicVAUKeys
	keyID               []byte
	// key and counter for k2_c2s_app_data
	k2_c2s_app_data         []byte
	k2_c2s_app_data_counter Counter
	// key to decrypt the responses from server
	k2_s2c_app_data []byte
	// request/response counter
	requestCounter Counter
	transport      http.Transport
}

func (c *Channel) Do(req *http.Request) (*http.Response, error) {
	data, err := c.EncryptRequest(req)
	if err != nil {
		return nil, fmt.Errorf("encrypting request: %w", err)
	}
	encResp, err := c.PostEncryptedRequest(data)
	if err != nil {
		return nil, fmt.Errorf("posting encrypted request: %w", err)
	}

	if encResp.StatusCode != http.StatusOK {
		messageError := new(MessageError)
		if err := cbor.NewDecoder(encResp.Body).Decode(messageError); err != nil {
			return nil, fmt.Errorf("decoding error: %w", err)
		}
		return nil, fmt.Errorf("server %s: %w", c.HostURL, messageError)
	}

	return c.DecryptResponse(encResp, req)
}

func (c *Channel) EncryptRequest(r *http.Request) ([]byte, error) {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return nil, fmt.Errorf("dumping request: %w", err)
	}
	return c.Encrypt(data)
}

func (c *Channel) Encrypt(data []byte) ([]byte, error) {
	header := make([]byte, 43)
	header[0] = Version
	header[1] = byte(c.Env)
	header[2] = HeaderRequest

	binary.BigEndian.PutUint64(header[3:], c.requestCounter.next())
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

	return append(header, ciphertext...), nil
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

	slog.Debug("Decrypting response", "data", string(data))

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

	return resp, nil
}

// PostEncryptedRequest sends previously encrypted data to the server, returning the raw "outer" response.
func (c *Channel) PostEncryptedRequest(data []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.HostURL.String(), bytes.NewReader(data))
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
