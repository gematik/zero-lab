package vau

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

type KeyPairs struct {
	ECKeyPair  *ECKeyPair
	KEMKeyPair *KEMKeyPair
}

func GenerateKeyPairs() (*KeyPairs, error) {
	ecKeyPair, err := GenerateRandomECKeyPair(elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("generating EC key pair: %w", err)
	}

	kemKeyPair, err := GenerateKEMKeyPair(kyber768.Scheme())
	if err != nil {
		return nil, fmt.Errorf("generating Kyber768 key pair: %w", err)
	}

	return &KeyPairs{
		ECKeyPair:  ecKeyPair,
		KEMKeyPair: kemKeyPair,
	}, nil
}

func OpenChannel(baseURLString string, env Env, httpClient *http.Client) (*Channel, error) {
	// validate base URL
	baseURL, err := url.Parse(baseURLString)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}
	// generate ephemeral key pairs for key exchange
	keys, err := GenerateKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key pairs: %w", err)
	}

	// create Message1
	m1 := Message1{}
	m1.MessageType = "M1"
	m1.ECDH_PK = keys.ECKeyPair.PublicData
	m1.Kyber768_PK = keys.KEMKeyPair.PublicData

	// construct URL for starting the channel
	startChannelURL := baseURL.ResolveReference(&url.URL{Path: "VAU"})
	slog.Debug("Sending Message1", "startChannelURL", startChannelURL.String())
	m1_cbor, firstHttpResponse, m2_cbor, m2, err := PostMessage[Message2](httpClient, startChannelURL.String(), m1)
	if err != nil {
		return nil, fmt.Errorf("sending Message1: %w", err)
	}

	// wouldn't it be better to have everything in the Message2?
	var channelID = firstHttpResponse.Header.Get("VAU-CID")
	matched, err := regexp.MatchString("^/[A-Za-z0-9-/]{1,200}$", channelID)
	if err != nil {
		return nil, fmt.Errorf("matching VAU-CID: %w", err)
	} else if !matched {
		return nil, fmt.Errorf("VAU-CID does not match regex")
	}
	// build the channel specific URL
	channelURL := baseURL.ResolveReference(&url.URL{Path: channelID})

	slog.Debug("Received Message2", "channelID", channelID, "channelURL", channelURL.String())

	ss_e_ecdh, err := keys.ECKeyPair.Decapsulate(&m2.ECDH_ct)
	if err != nil {
		return nil, fmt.Errorf("decapsulating ECDH: %w", err)
	}

	ss_e_kem, err := keys.KEMKeyPair.Decapsulate(m2.Kyber768_ct)
	if err != nil {
		return nil, fmt.Errorf("decapsulating Kyber768: %w", err)
	}

	c_k1_c2s, c_k1_s2c, err := KemKDF1(ss_e_ecdh, ss_e_kem)
	if err != nil {
		log.Fatalf("computing KDF: %v", err)
	}

	plaintext, err := AEADDecrypt(c_k1_s2c, m2.AEAD_ct)
	if err != nil {
		log.Fatalf("decrypting: %v", err)
	}

	var signedPubKeys = new(SignedPublicVAUKeys)
	if err = cbor.Unmarshal(plaintext, signedPubKeys); err != nil {
		log.Fatalf("decoding VAU keys: %v", err)
	}

	var pubKeys = new(PublicVAUKeys)
	if err = cbor.Unmarshal(signedPubKeys.SignedPubKeysRaw, pubKeys); err != nil {
		log.Fatalf("decoding public keys: %v", err)
	}

	signedPubKeys.SignedPubKeys = pubKeys

	if err := validateSignedPublicVAUKeys(httpClient, baseURL, signedPubKeys); err != nil {
		return nil, fmt.Errorf("validating signed public VAU keys: %w", err)
	}

	// prepare Message3
	ecdh_ss, ecdh_ct, err := pubKeys.ECDH_PK.Encapsulate()
	if err != nil {
		log.Fatalf("encapsulating ECDH: %v", err)
	}

	kem_ss, kem_ct, err := pubKeys.Kyber768_PK.Encapsulate()
	if err != nil {
		return nil, fmt.Errorf("encapsulating Kyber768: %w", err)
	}

	k2_c2s_key_confirmation, k2_c2s_app_data, k2_s2c_key_confirmation, k2_s2c_app_data, key_id, err := KemKDF2(ss_e_ecdh, ss_e_kem, ecdh_ss, kem_ss)
	if err != nil {
		return nil, fmt.Errorf("computing KDF2: %w", err)
	}

	m3_inner := Message3Inner{
		ECDH_ct:     *ecdh_ct,
		Kyber768_ct: kem_ct,
		ERP:         false,
		ESO:         false,
	}

	m3_inner_cbor, err := cbor.Marshal(m3_inner)
	if err != nil {
		log.Fatalf("marshaling M3Inner: %v", err)
	}

	m3_inner_cbor_encrypted, err := AEADEncrypt(c_k1_c2s, m3_inner_cbor)
	if err != nil {
		log.Fatalf("encrypting M3Inner: %v", err)
	}

	transcript := m1_cbor
	transcript = append(transcript, m2_cbor...)
	transcript = append(transcript, m3_inner_cbor_encrypted...)

	transcript_hash := sha256.Sum256(transcript)
	m3_aead_ct_key_confirmation, err := AEADEncrypt(k2_c2s_key_confirmation, transcript_hash[:])
	if err != nil {
		log.Fatalf("encrypting M3 key confirmation: %v", err)
	}

	m3 := Message3{
		MessageType:              "M3",
		AEAD_ct:                  m3_inner_cbor_encrypted,
		AEAD_ct_key_confirmation: m3_aead_ct_key_confirmation,
	}

	slog.Debug("Sending Message3", "channelURL", channelURL.String())

	m3_cbor, _, _, m4, err := PostMessage[Message4](httpClient, channelURL.String(), m3)
	if err != nil {
		return nil, fmt.Errorf("sending Message3: %w", err)
	}
	slog.Debug("Received Message4", "channelURL", channelURL.String())

	transcript = m1_cbor
	transcript = append(transcript, m2_cbor...)
	transcript = append(transcript, m3_cbor...)
	transcript_hash = sha256.Sum256(transcript)

	m4_key_confirmation, err := AEADDecrypt(k2_s2c_key_confirmation, m4.AEAD_ct_key_confirmation)
	if err != nil {
		return nil, fmt.Errorf("decrypting Message4 key confirmation: %w", err)
	}

	if !bytes.Equal(transcript_hash[:], m4_key_confirmation) {
		return nil, fmt.Errorf("Message4 key confirmation does not match")
	}

	channel := &Channel{
		httpClient:          httpClient,
		Env:                 EnvNonPU,
		ID:                  channelID,
		ChannelURL:          channelURL,
		SignedPublicVAUKeys: signedPubKeys,
		keyID:               key_id,
		k2_c2s_app_data:     k2_c2s_app_data,
		k2_s2c_app_data:     k2_s2c_app_data,
	}

	return channel, nil
}

func PostMessage[M interface{}](httpClient *http.Client, url string, requestMessage interface{}) ([]byte, *http.Response, []byte, *M, error) {
	// marshal Message1 to CBOR
	requestMessageCbor, err := cbor.Marshal(requestMessage)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshaling Message1: %w", err)
	}

	// create request to VAU
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestMessageCbor))
	if err != nil {
		log.Fatalf("creating request to VAU: %v", err)
	}
	req.Header.Set("Content-Type", "application/cbor")

	// send request to VAU
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sending request to VAU: %w", err)
	}
	defer resp.Body.Close()

	// unmarshal ResponseMessage from CBOR
	responseCbor, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, nil, fmt.Errorf("VAU returned status %v, body: %s", resp.StatusCode, responseCbor)
	}

	responseMessage := new(M)
	if err := cbor.Unmarshal(responseCbor, &responseMessage); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	return requestMessageCbor, resp, responseCbor, responseMessage, nil
}

func KemKDF1(ss_e_ecdh, ss_e_kyber768 []byte) (k1_c2s []byte, k1_s2c []byte, err error) {
	ss := append(ss_e_ecdh, ss_e_kyber768...)

	hkdf := hkdf.New(sha256.New, ss, nil, []byte(""))
	derived := make([]byte, 2*32)
	_, err = io.ReadFull(hkdf, derived)
	if err != nil {
		return nil, nil, fmt.Errorf("reading from HKDF: %w", err)
	}

	return derived[:32], derived[32:], nil
}

func KemKDF2(ecdhSS1, kemSS1, ecdhSS2, kemSS2 []byte) (k2_c2s_key_confirmation, k2_c2s_app_data, k2_s2c_key_confirmation, k2_s2c_app_data, key_id []byte, err error) {
	ss := append(append(ecdhSS1, kemSS1...), append(ecdhSS2, kemSS2...)...)
	hkdf := hkdf.New(sha256.New, ss, nil, []byte(""))
	// read 5x32 bytes from hkdf
	derived := make([]byte, 5*32)
	_, err = io.ReadFull(hkdf, derived)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("reading from HKDF: %w", err)
	}
	return derived[:32], derived[32:64], derived[64:96], derived[96:128], derived[128:], nil
}

func AEADEncrypt(key, plaintext []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func AEADDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM: %w", err)
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aesGCM.NonceSize()]
	cypertext := ciphertext[aesGCM.NonceSize():]

	return aesGCM.Open(nil, nonce, cypertext, nil)
}

func validateSignedPublicVAUKeys(httpClient *http.Client, baseURL *url.URL, signedPubKeys *SignedPublicVAUKeys) error {
	certDataPath := fmt.Sprintf("/CertData.%x-%d", signedPubKeys.CertHash, signedPubKeys.Cdv)
	certDataURL := baseURL.ResolveReference(&url.URL{Path: certDataPath})

	resp, err := httpClient.Get(certDataURL.String())
	if err != nil {
		return fmt.Errorf("getting CertData: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("getting certData from '%s' returned http status %v", certDataURL.String(), resp.StatusCode)
	}

	defer resp.Body.Close()
	certData := new(CertData)
	if err := cbor.NewDecoder(resp.Body).Decode(certData); err != nil {
		return fmt.Errorf("decoding CertData: %w", err)
	}

	slog.Debug("Received CertData", "cert", base64.StdEncoding.EncodeToString(certData.Cert.Raw), "ca", base64.StdEncoding.EncodeToString(certData.CACert.Raw))

	slog.Warn("VAU Cert validation is not implemented", "cert", certData.Cert.Subject.CommonName)
	slog.Warn("VAU CA validation is not implemented", "ca", certData.CACert.Subject.CommonName)

	for _, cert := range certData.RCAChain {
		slog.Warn("VAU Root CA validation is not implemented", "cert", cert.Subject.CommonName)
	}

	slog.Warn("VAU Host keys validation is not implemented")
	return nil
}
