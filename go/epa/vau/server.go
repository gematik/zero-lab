// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package vau

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"uuid"

	"github.com/fxamacker/cbor/v2"
)

// ChannelState is what Server remembers of a channel: the handshake messages, the K1
// material, and the K2 keys once Message3 is through.
type ChannelState struct {
	ID                  string
	Message1Raw         []byte
	Message2Raw         []byte
	K1SSECDH            []byte
	K1SSKEM             []byte
	K1C2S               []byte
	K1S2C               []byte
	KeyID               []byte
	K2C2SAppData        []byte
	K2S2CAppData        []byte
	K2S2CAppDataCounter Counter
}

// Server is a VAU endpoint for tests: its keys are generated at start and carry neither
// signature nor certificate, and its channels live in memory. It is no production VAU.
type Server struct {
	mux                 *http.ServeMux
	keyPairs            *KeyPairs
	signedPublicKeys    *SignedPublicVAUKeys
	signedPublicKeysRaw []byte
	channels            map[string]*ChannelState
}

// NewServer generates the server's keys and sets up its routes.
func NewServer() (s *Server, err error) {
	s = &Server{
		mux:      http.NewServeMux(),
		channels: make(map[string]*ChannelState),
	}

	s.mux.HandleFunc("POST /VAU", s.HandleMessage1)
	s.mux.HandleFunc("POST /{cid}", s.HandleByContentType)
	// TODO: add regex to match hash and version
	s.mux.HandleFunc("GET /CertData", s.HandleCertData)

	// TODO: implement key management
	s.keyPairs, err = GenerateKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("generating key pairs: %w", err)
	}

	s.signedPublicKeys = &SignedPublicVAUKeys{
		SignedPubKeys: &PublicVAUKeys{
			ECDHPK:     s.keyPairs.ECKeyPair.PublicData,
			Kyber768PK: s.keyPairs.KEMKeyPair.PublicData,
			IssuedAt:   0,
			ExpiresAt:  0,
			Commment:   "Server keys are not implemented yet",
		},
		Cdv: 1,
	}

	s.signedPublicKeys.SignedPubKeysRaw, err = cbor.Marshal(s.signedPublicKeys.SignedPubKeys)
	if err != nil {
		return nil, fmt.Errorf("marshaling signed public keys: %w", err)
	}

	s.signedPublicKeysRaw, err = cbor.Marshal(s.signedPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("marshaling signed public keys: %w", err)
	}

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info("Request", "method", r.Method, "url", r.URL.String())
	s.mux.ServeHTTP(w, r)
}

// HandleByContentType routes a POST on a channel: Message3 as application/cbor, a nested
// request as application/octet-stream.
func (s *Server) HandleByContentType(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Content-Type") {
	case "application/cbor":
		s.HandleMessage3(w, r)
	case "application/octet-stream":
		s.HandleNestedRequest(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// HandleMessage1 answers Message1 with Message2 and creates the channel, whose path goes
// back in the VAU-CID header.
func (s *Server) HandleMessage1(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/cbor" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	m1cbor, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("reading Message1", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	m1 := new(Message1)
	if err := cbor.Unmarshal(m1cbor, m1); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ecdhSS, ecdhCt, err := m1.ECDHPK.Encapsulate()
	if err != nil {
		slog.Error("encapsulating ECDH public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	kemSS, kemCt, err := m1.Kyber768PK.Encapsulate()
	if err != nil {
		slog.Error("encapsulating Kyber768 public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	k1C2S, k1S2C, err := KemKDF1(ecdhSS, kemSS)
	if err != nil {
		slog.Error("computing KEM KDF1", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// encrypt the signed public keys
	slog.Info("Encrypting signed public keys")
	encryptedSignedPublicKeys, err := AEADEncrypt(k1S2C, s.signedPublicKeysRaw)
	if err != nil {
		slog.Error("encrypting signed public keys", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	m2 := &Message2{
		MessageType: "M2",
		ECDHCt:      *ecdhCt,
		Kyber768Ct:  kemCt,
		AEADCt:      encryptedSignedPublicKeys,
	}

	vauCid := "/" + uuid.NewV4().String()

	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("VAU-CID", vauCid)

	m2cbor, err := cbor.Marshal(m2)
	if err != nil {
		slog.Error("marshaling Message2", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	channelState := &ChannelState{
		ID:          vauCid,
		Message1Raw: m1cbor,
		Message2Raw: m2cbor,
		K1SSECDH:    ecdhSS,
		K1SSKEM:     kemSS,
		K1C2S:       k1C2S,
		K1S2C:       k1S2C,
	}

	s.channels[vauCid] = channelState

	if _, err := w.Write(m2cbor); err != nil {
		slog.Error("writing Message2", "error", err)
	}
}

// HandleMessage3 checks the key confirmation of Message3, installs the K2 keys and answers
// with Message4.
func (s *Server) HandleMessage3(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	channelState, ok := s.channels["/"+cid]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	defer r.Body.Close()

	m3cbor, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("reading Message3", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m3 := new(Message3)
	if err := cbor.Unmarshal(m3cbor, m3); err != nil {
		slog.Error("unmarshaling Message3", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m3InnerCBOR, err := AEADDecrypt(channelState.K1C2S, m3.AEADCt)
	if err != nil {
		slog.Error("decrypting Message3", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m3Inner := new(Message3Inner)
	if err := cbor.Unmarshal(m3InnerCBOR, m3Inner); err != nil {
		slog.Error("unmarshaling Message3Inner", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	k2C2SKeyConfirmation, k2C2SAppData, k2S2CKeyConfirmation, k2S2CAppData, keyID, err := s.Decapsulate(channelState.K1SSECDH, channelState.K1SSKEM, &m3Inner.ECDHCt, m3Inner.Kyber768Ct)
	if err != nil {
		slog.Error("decapsulating", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	transcript := channelState.Message1Raw
	transcript = append(transcript, channelState.Message2Raw...)
	transcript = append(transcript, m3.AEADCt...)

	transcriptHash := sha256.Sum256(transcript)

	m3KeyConfirmation, err := AEADDecrypt(k2C2SKeyConfirmation, m3.AEADCtKeyConfirmation)
	if err != nil {
		slog.Error("decrypting Message3 key confirmation", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !bytes.Equal(transcriptHash[:], m3KeyConfirmation) {
		slog.Error("transcript hash and Message3 key confirmation do not match", "transcript_hash", transcriptHash[:], "m3_key_confirmation", m3KeyConfirmation)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// update state
	channelState.K1C2S = nil
	channelState.K1S2C = nil
	channelState.KeyID = keyID
	channelState.K2C2SAppData = k2C2SAppData
	channelState.K2S2CAppData = k2S2CAppData

	// create Message4
	transcript = channelState.Message1Raw
	transcript = append(transcript, channelState.Message2Raw...)
	transcript = append(transcript, m3cbor...)
	transcriptHash = sha256.Sum256(transcript)

	aeadCtKeyConfirmation, err := AEADEncrypt(k2S2CKeyConfirmation, transcriptHash[:])
	if err != nil {
		slog.Error("encrypting Message4 key confirmation", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	m4 := &Message4{
		MessageType:           "M4",
		AEADCtKeyConfirmation: aeadCtKeyConfirmation,
	}

	m4cbor, err := cbor.Marshal(m4)
	if err != nil {
		slog.Error("marshaling Message4", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/cbor")
	if _, err := w.Write(m4cbor); err != nil {
		slog.Error("writing Message4", "error", err)
	}
}

// Decapsulate opens the ciphertexts of Message3 and derives the K2 keys from them and the
// shared secrets of Message1.
func (s *Server) Decapsulate(ecdhSS1, kemSS1 []byte, ecdhCt *ECDHData, kemCt []byte) (k2C2SKeyConfirmation, k2C2SAppData, k2S2CKeyConfirmation, k2S2CAppData, keyID []byte, err error) {
	ecdhSS2, err := s.keyPairs.ECKeyPair.Decapsulate(ecdhCt)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("decapsulating ECDH: %w", err)
	}

	kemSS2, err := s.keyPairs.KEMKeyPair.Decapsulate(kemCt)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("decapsulating Kyber768: %w", err)
	}

	return KemKDF2(ecdhSS1, kemSS1, ecdhSS2, kemSS2)
}

// HandleCertData always answers 500: the server has no certificates to publish.
func (s *Server) HandleCertData(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	version := r.PathValue("version")
	slog.Info("CertData received", "hash", hash, "version", version)
	w.WriteHeader(http.StatusInternalServerError)
	if _, err := w.Write([]byte("CertData")); err != nil {
		slog.Error("writing CertData", "error", err)
	}
}

// HandleNestedRequest opens a nested request and answers every one with a fixed 200.
func (s *Server) HandleNestedRequest(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cid")
	channelState, ok := s.channels["/"+cid]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	decrypted, err := s.DecryptNestedRequestData(channelState, r)
	if err != nil {
		slog.Error("decrypting nested request", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	slog.Info("Decrypted nested request", "decrypted", decrypted)

	nestedResp := http.Response{
		Header:     make(http.Header),
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("Hello, World!"))),
	}

	nestedResp.Header.Set("Content-Type", "application/text")

	nestedRespData, err := httputil.DumpResponse(&nestedResp, true)
	if err != nil {
		slog.Error("dumping nested response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	encrypted, err := s.EncryptNestedResponseData(channelState, nestedRespData)
	if err != nil {
		slog.Error("encrypting nested response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	slog.Info("Sending nested response", "response", string(nestedRespData))

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(encrypted); err != nil {
		slog.Error("writing nested response", "error", err)
	}
}

// EncryptNestedResponseData seals data as a nested response of channelState.
func (s *Server) EncryptNestedResponseData(channelState *ChannelState, data []byte) ([]byte, error) {
	header := make([]byte, 43)
	header[0] = Version
	header[1] = byte(EnvNonPU)
	header[2] = HeaderResponse
	copy(header[11:43], channelState.KeyID)

	aes, err := aes.NewCipher(channelState.K2S2CAppData)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM: %w", err)
	}

	// prepare iv
	iv := make([]byte, 12)

	// increment counter
	counter := channelState.K2S2CAppDataCounter.next()

	// read random bits to have full iv size
	if _, err := io.ReadAtLeast(rand.Reader, iv, 4); err != nil {
		return nil, fmt.Errorf("generating iv: %w", err)
	}
	// add 64 bit from counter
	binary.LittleEndian.PutUint64(iv[4:], counter)

	ciphertext := aesGCM.Seal(iv, iv, data, header)

	return append(header, ciphertext...), nil
}

// DecryptNestedRequestData reads, checks and opens the nested request in the body of r.
func (s *Server) DecryptNestedRequestData(channelState *ChannelState, r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("reading request: %w", err)
	}

	if len(data) < 43 {
		return nil, fmt.Errorf("invalid data length: %d", len(data))
	}
	header := data[:43]
	ciphertext := data[43:]

	if header[0] != Version {
		return nil, fmt.Errorf("invalid version: %d", header[0])
	}
	// TODO: check if the environment is the same
	if header[1] != byte(EnvNonPU) {
		return nil, fmt.Errorf("invalid env: %d", header[1])
	}
	if header[2] != HeaderRequest {
		return nil, fmt.Errorf("invalid header: %d", header[2])
	}

	// check if the keyID is the same
	if string(header[11:43]) != string(channelState.KeyID) {
		return nil, fmt.Errorf("invalid keyID: %s", header[11:43])
	}

	aes, err := aes.NewCipher(channelState.K2C2SAppData)
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

	return plaintext, nil
}
