package asl

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
	"regexp"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/segmentio/ksuid"
)

type ChannelState struct {
	ID                      string
	Message1Raw             []byte
	Message2Raw             []byte
	K1_ss_ecdh              []byte
	K1_ss_kem               []byte
	K1_c2s                  []byte
	K1_s2c                  []byte
	KeyID                   []byte
	K2_c2s_app_data         []byte
	K2_s2c_app_data         []byte
	K2_s2c_app_data_counter Counter
}

type Server struct {
	profile             Profile
	mux                 *http.ServeMux
	keyPairs            *KeyPairs
	signedPublicKeys    *SignedPublicKeys
	signedPublicKeysRaw []byte
	certData            *CertData
	channels            sync.Map
}

func NewServer() (s *Server, err error) {
	s = &Server{
		mux:      http.NewServeMux(),
		channels: sync.Map{},
		profile:  ProfileZetaAsl,
	}

	s.mux.HandleFunc(fmt.Sprintf("POST %s", s.profile.ChannelPath), s.HandleMessage1)
	s.mux.HandleFunc(fmt.Sprintf("POST %s/{cidFragment}", s.profile.ChannelPath), s.HandleByContentType)

	// it's a bit ugly since the mux doesn't support regex and very strict about fragment wildcards
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		regex := regexp.MustCompile(`^/CertData\.([0-9a-f]+)-(\d+)$`)
		matches := regex.FindStringSubmatch(r.URL.Path)
		if matches == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		r.SetPathValue("hash", matches[1])
		r.SetPathValue("version", matches[2])
		s.HandleCertData(w, r)
	})

	// TODO: implement key management
	s.keyPairs, err = GenerateKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("generating key pairs: %w", err)
	}

	s.certData, err = createMockCertData()
	if err != nil {
		return nil, fmt.Errorf("generating cert data: %w", err)
	}

	certHash := sha256.Sum256(s.certData.Cert.Raw)

	s.signedPublicKeys = &SignedPublicKeys{
		SignedPubKeys: &PublicKeys{
			ECDH_PK:       s.keyPairs.ECKeyPair.PublicData,
			KemPublicData: s.keyPairs.KEMKeyPair.PublicData,
			IssuedAt:      0,
			ExpiresAt:     0,
			Commment:      "Server keys are not implemented yet",
		},
		CertHash: certHash[:],
		Cdv:      1,
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

func (s *Server) HandleByContentType(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/cbor" {
		s.HandleMessage3(w, r)
	} else if r.Header.Get("Content-Type") == "application/octet-stream" {
		s.HandleNestedRequest(w, r)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

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

	ecdh_ss, ecdh_ct, err := m1.ECDH_PK.Encapsulate()
	if err != nil {
		slog.Error("encapsulating ECDH public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	kem_ss, kem_ct, err := m1.KemPublicData.Encapsulate()
	if err != nil {
		slog.Error("encapsulating Kyber768 public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	k1_c2s, k1_s2c, err := KemKDF1(ecdh_ss, kem_ss)
	if err != nil {
		slog.Error("computing KEM KDF1", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// encrypt the signed public keys
	slog.Info("Encrypting signed public keys")
	encryptedSignedPublicKeys, err := AEADEncrypt(k1_s2c, s.signedPublicKeysRaw)
	if err != nil {
		slog.Error("encrypting signed public keys", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	m2 := &Message2{
		MessageType: "M2",
		ECDH_ct:     *ecdh_ct,
		Kyber768_ct: kem_ct,
		AEAD_ct:     encryptedSignedPublicKeys,
	}

	cid := fmt.Sprintf("%s/%s", s.profile.ChannelPath, ksuid.New().String())

	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set(s.profile.HeaderNameCid, cid)

	m2cbor, err := cbor.Marshal(m2)
	if err != nil {
		slog.Error("marshaling Message2", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	channelState := &ChannelState{
		ID:          cid,
		Message1Raw: m1cbor,
		Message2Raw: m2cbor,
		K1_ss_ecdh:  ecdh_ss,
		K1_ss_kem:   kem_ss,
		K1_c2s:      k1_c2s,
		K1_s2c:      k1_s2c,
	}

	// TODO: use proper state management
	s.channels.Store(cid, channelState)

	w.Write(m2cbor)
}

func (s *Server) HandleMessage3(w http.ResponseWriter, r *http.Request) {
	cidFragment := r.PathValue("cidFragment")
	cid := fmt.Sprintf("%s/%s", s.profile.ChannelPath, cidFragment)
	val, ok := s.channels.Load(cid)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	channelState, ok := val.(*ChannelState)
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

	m3_inner_cbor, err := AEADDecrypt(channelState.K1_c2s, m3.AEAD_ct)
	if err != nil {
		slog.Error("decrypting Message3", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	m3_inner := new(Message3Inner)
	if err := cbor.Unmarshal(m3_inner_cbor, m3_inner); err != nil {
		slog.Error("unmarshaling Message3Inner", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	k2_c2s_key_confirmation, k2_c2s_app_data, k2_s2c_key_confirmation, k2_s2c_app_data, key_id, err := s.Decapsulate(channelState.K1_ss_ecdh, channelState.K1_ss_kem, &m3_inner.ECDH_ct, m3_inner.Kyber768_ct)
	if err != nil {
		slog.Error("decapsulating", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	transcript := channelState.Message1Raw
	transcript = append(transcript, channelState.Message2Raw...)
	transcript = append(transcript, m3.AEAD_ct...)

	transcript_hash := sha256.Sum256(transcript)

	m3_key_confirmation, err := AEADDecrypt(k2_c2s_key_confirmation, m3.AEAD_ct_key_confirmation)
	if err != nil {
		slog.Error("decrypting Message3 key confirmation", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !bytes.Equal(transcript_hash[:], m3_key_confirmation) {
		slog.Error("transcript hash and Message3 key confirmation do not match", "transcript_hash", transcript_hash[:], "m3_key_confirmation", m3_key_confirmation)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// update state
	channelState.K1_c2s = nil
	channelState.K1_s2c = nil
	channelState.KeyID = key_id
	channelState.K2_c2s_app_data = k2_c2s_app_data
	channelState.K2_s2c_app_data = k2_s2c_app_data

	// create Message4
	transcript = channelState.Message1Raw
	transcript = append(transcript, channelState.Message2Raw...)
	transcript = append(transcript, m3cbor...)
	transcript_hash = sha256.Sum256(transcript)

	aead_ct_key_confirmation, err := AEADEncrypt(k2_s2c_key_confirmation, transcript_hash[:])
	if err != nil {
		slog.Error("encrypting Message4 key confirmation", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	m4 := &Message4{
		MessageType:              "M4",
		AEAD_ct_key_confirmation: aead_ct_key_confirmation,
	}

	m4cbor, err := cbor.Marshal(m4)
	if err != nil {
		slog.Error("marshaling Message4", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/cbor")
	w.Write(m4cbor)

}

func (s *Server) Decapsulate(ecdh_ss1, kem_ss1 []byte, ecdh_ct *ECDHData, kem_ct []byte) (k2_c2s_key_confirmation, k2_c2s_app_data, k2_s2c_key_confirmation, k2_s2c_app_data, key_id []byte, err error) {
	ecdh_ss2, err := s.keyPairs.ECKeyPair.Decapsulate(ecdh_ct)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("decapsulating ECDH: %w", err)
	}

	kem_ss2, err := s.keyPairs.KEMKeyPair.Decapsulate(kem_ct)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("decapsulating Kyber768: %w", err)
	}

	return KemKDF2(ecdh_ss1, kem_ss1, ecdh_ss2, kem_ss2)
}

func (s *Server) HandleCertData(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	version := r.PathValue("version")
	slog.Info("CertData received", "hash", hash, "version", version)
	certDataBytes, err := cbor.Marshal(s.certData)
	if err != nil {
		slog.Error("marshaling CertData", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/cbor")
	w.Write(certDataBytes)

}

func (s *Server) HandleNestedRequest(w http.ResponseWriter, r *http.Request) {
	cid := r.PathValue("cidFragment")
	cid = fmt.Sprintf("%s/%s", s.profile.ChannelPath, cid)
	val, ok := s.channels.Load(cid)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	channelState, ok := val.(*ChannelState)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// decrypt the nested request

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
	w.Write(encrypted)
}

func (s *Server) EncryptNestedResponseData(channelState *ChannelState, data []byte) ([]byte, error) {
	header := make([]byte, 43)
	header[0] = Version
	header[1] = byte(EnvNonPU)
	header[2] = HeaderResponse
	copy(header[11:43], channelState.KeyID)

	aes, err := aes.NewCipher(channelState.K2_s2c_app_data)
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
	counter := channelState.K2_s2c_app_data_counter.next()

	// read random bits to have full iv size
	if _, err := io.ReadAtLeast(rand.Reader, iv, 4); err != nil {
		return nil, fmt.Errorf("generating iv: %w", err)
	}
	// add 64 bit from counter
	binary.LittleEndian.PutUint64(iv[4:], counter)

	ciphertext := aesGCM.Seal(iv, iv, data, header)

	return append(header, ciphertext...), nil
}

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

	aes, err := aes.NewCipher(channelState.K2_c2s_app_data)
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
