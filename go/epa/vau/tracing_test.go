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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// tracingRecorder notes the A_24477 header of every outer request on the channel.
type tracingRecorder struct {
	next http.Handler
	mu   sync.Mutex
	seen []string
}

func (r *tracingRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost && req.Header.Get("Content-Type") == "application/octet-stream" {
		r.mu.Lock()
		r.seen = append(r.seen, req.Header.Get(NonPUTracingHeader))
		r.mu.Unlock()
	}
	r.next.ServeHTTP(w, req)
}

func tracedChannel(t *testing.T, env Env) (*Channel, *tracingRecorder) {
	t.Helper()
	server, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	recorder := &tracingRecorder{next: server}
	stub := httptest.NewServer(recorder)
	t.Cleanup(stub.Close)
	channel, err := OpenChannel(stub.URL, env, stub.Client())
	if err != nil {
		t.Fatal(err)
	}
	return channel, recorder
}

func get(t *testing.T, channel *Channel) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/epa/authz/v1/getNonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := channel.Do(req); err == nil {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	}
}

// A_24477: outside production, every outer request after the key exchange names K2_c2s_app_data and
// K2_s2c_app_data, base64 and separated by a space, in that order.
func TestA_24477_ANonPUChannelDisclosesItsKeysOnEveryRequest(t *testing.T) {
	channel, recorder := tracedChannel(t, EnvNonPU)
	get(t, channel)
	get(t, channel)
	want := base64.StdEncoding.EncodeToString(channel.k2C2SAppData) + " " + base64.StdEncoding.EncodeToString(channel.k2S2CAppData)
	if len(recorder.seen) != 2 {
		t.Fatalf("%d outer requests", len(recorder.seen))
	}
	for i, got := range recorder.seen {
		if got != want {
			t.Errorf("request %d: %s = %q, want %q", i, NonPUTracingHeader, got, want)
		}
	}
}

// A_24477, A_24478: a production channel never discloses its keys.
func TestA_24477_AProductionChannelNeverDisclosesItsKeys(t *testing.T) {
	channel, recorder := tracedChannel(t, EnvPU)
	get(t, channel)
	if len(recorder.seen) != 1 {
		t.Fatalf("%d outer requests", len(recorder.seen))
	}
	if recorder.seen[0] != "" {
		t.Errorf("%s sent in production: %q", NonPUTracingHeader, recorder.seen[0])
	}
}
