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
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// A_24633: a response shorter than 72 bytes is refused, never sliced past its end.
func TestA_24633_ATooShortMessageIsAnError(t *testing.T) {
	keyID := bytes.Repeat([]byte{7}, 32)
	channel := &Channel{Env: EnvNonPU, keyID: keyID, k2S2CAppData: make([]byte, 32)}
	header := append([]byte{Version, byte(EnvNonPU), HeaderResponse}, make([]byte, 8)...)
	header = append(header, keyID...)
	for _, size := range []int{0, 42, 43, 50, 55, 70, 71} {
		data := append(append([]byte{}, header...), make([]byte, max(0, size-len(header)))...)[:size]
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if _, err := channel.Decrypt(data, req, 0); err == nil {
			t.Errorf("%d bytes accepted", size)
		}
	}
}

// corruptingServer flips one byte of the answer to Message1.
type corruptingServer struct {
	inner http.Handler
	at    int
}

func (c corruptingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/VAU" {
		c.inner.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	c.inner.ServeHTTP(rec, r)
	body := rec.Body.Bytes()
	if c.at < len(body) {
		body[c.at] ^= 0xff
	}
	maps.Copy(w.Header(), rec.Header())
	w.WriteHeader(rec.Code)
	_, _ = w.Write(body)
}

// A server that answers Message1 with damaged data makes OpenChannel fail, not exit the process.
func TestADamagedMessage2IsAnErrorNotAnExit(t *testing.T) {
	failed := 0
	for at := 0; at < 1300; at += 13 {
		server, err := NewServer()
		if err != nil {
			t.Fatal(err)
		}
		stub := httptest.NewServer(corruptingServer{server, at})
		if _, err := OpenChannel(stub.URL, EnvNonPU, stub.Client()); err != nil {
			failed++
		}
		stub.Close()
	}
	if failed == 0 {
		t.Fatal("no damage was noticed")
	}
}

// A_24628-01: the channel keeps the environment it was opened for, so its messages carry that PU/nonPU byte.
func TestA_24628_AChannelCarriesTheEnvironmentItWasOpenedFor(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	stub := httptest.NewServer(server)
	defer stub.Close()
	channel, err := OpenChannel(stub.URL, EnvPU, stub.Client())
	if err != nil {
		t.Fatal(err)
	}
	if channel.Env != EnvPU {
		t.Errorf("Env = %d", channel.Env)
	}
}

// sealedResponse is a response of server's channel state to the request that carried
// requestCounter, as the Aktensystem seals it.
func sealedResponse(t *testing.T, state *ChannelState, requestCounter uint64) []byte {
	t.Helper()
	inner := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	data, err := new(Server).EncryptNestedResponseData(state, requestCounter, []byte(inner))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A_24633: a response is taken only for the request whose counter its header carries.
func TestA_24633_AResponseCarryingAnotherRequestsCounterIsRefused(t *testing.T) {
	keyID := bytes.Repeat([]byte{7}, 32)
	key := bytes.Repeat([]byte{9}, 32)
	channel := &Channel{Env: EnvNonPU, keyID: keyID, k2S2CAppData: key, ChannelURL: &url.URL{}}
	state := &ChannelState{KeyID: keyID, K2S2CAppData: key}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	resp, err := channel.Decrypt(sealedResponse(t, state, 5), req, 5)
	if err != nil {
		t.Fatalf("own response: %v", err)
	}
	_ = resp.Body.Close()
	for _, counter := range []uint64{0, 4, 6, 1 << 63} {
		if _, err := channel.Decrypt(sealedResponse(t, state, counter), req, 5); !errors.Is(err, ErrResponseCounter) {
			t.Errorf("counter %d: err = %v", counter, err)
		}
	}
}

// replayingServer answers every nested request after the first with the first one's response.
type replayingServer struct {
	inner http.Handler
	first []byte
}

func (s *replayingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		s.inner.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	s.inner.ServeHTTP(rec, r)
	if s.first == nil {
		s.first = rec.Body.Bytes()
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(s.first)
}

// A_24633: an Aktensystem, or anyone on the path, that answers a request with the response to
// an earlier one is refused, though that response decrypts under the channel's key.
func TestA_24633_AReplayedResponseOfAnEarlierRequestIsRefused(t *testing.T) {
	server, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	stub := httptest.NewServer(&replayingServer{inner: server})
	defer stub.Close()
	channel, err := OpenChannel(stub.URL, EnvNonPU, stub.Client())
	if err != nil {
		t.Fatal(err)
	}
	do := func() error {
		req, err := http.NewRequest(http.MethodGet, "/epa/authz/v1/getNonce", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := channel.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := do(); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := do(); !errors.Is(err, ErrResponseCounter) {
		t.Fatalf("second request: err = %v", err)
	}
}
