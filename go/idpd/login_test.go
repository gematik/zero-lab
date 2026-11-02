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

package idpd

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// readTokenKey decrypts a key_verifier as the IDP-Dienst does, ECDH-ES and A256GCM to puk_idp_enc, which josebp only does
// one way.
func readTokenKey(t *testing.T, idp *fakeIDP, compact string) TokenKeyPayload {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 5 || parts[1] != "" {
		t.Fatalf("no ECDH-ES compact JWE: %s", compact)
	}
	decode := func(part string) []byte {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var header struct {
		EPK josebp.JSONWebKey `json:"epk"`
	}
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	ephemeral, ok := header.EPK.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("epk is a %T", header.EPK.Key)
	}
	shared, err := brainpool.ECDH(idp.key, ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7518 section 4.6.2, Concat KDF, one round for 256 bits; PartyUInfo and PartyVInfo are empty.
	const algorithm = "A256GCM"
	var input bytes.Buffer
	input.Write([]byte{0, 0, 0, 1})
	input.Write(shared)
	_ = binary.Write(&input, binary.BigEndian, uint32(len(algorithm)))
	input.WriteString(algorithm)
	input.Write(make([]byte, 8))
	_ = binary.Write(&input, binary.BigEndian, uint32(256))
	key := sha256.Sum256(input.Bytes())
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, decode(parts[2]), append(decode(parts[3]), decode(parts[4])...), []byte(parts[0]))
	if err != nil {
		t.Fatal(err)
	}
	var payload TokenKeyPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// issuedTokens is what the fake token endpoint hands out, kept for a test to look for in the log.
type issuedTokens struct {
	tokenKey, verifier, keyVerifier, accessToken, idToken, sealedAccessToken, sealedIDToken string
}

// serveTokens makes the fake IDP answer the code exchange; withIDToken says whether the response has an ID token.
func serveTokens(t *testing.T, idp *fakeIDP, issued *issuedTokens, withIDToken bool) {
	t.Helper()
	idp.token = func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		issued.keyVerifier = r.PostForm.Get("key_verifier")
		payload := readTokenKey(t, idp, issued.keyVerifier)
		issued.tokenKey, issued.verifier = payload.TokenKey, payload.CodeVerifier
		tokenKey, err := base64.RawURLEncoding.DecodeString(payload.TokenKey)
		if err != nil {
			t.Error(err)
			return
		}
		issued.idToken = signIDToken(t, idp.key, josebp.AlgorithmNameBP256R1, map[string]any{"iss": idp.URL, "aud": "client", "nonce": "nonce-value", "exp": time.Now().Add(time.Hour).Unix()})
		issued.accessToken = "inner-access-token-value"
		seal := func(inner string) string {
			return encryptDir(t, tokenKey, jose.DIRECT, jose.A256GCM, fmt.Sprintf(`{"njwt":%q}`, inner))
		}
		issued.sealedAccessToken = seal(issued.accessToken)
		response := map[string]any{"access_token": issued.sealedAccessToken, "token_type": "Bearer", "expires_in": 300}
		if withIDToken {
			issued.sealedIDToken = seal(issued.idToken)
			response["id_token"] = issued.sealedIDToken
		}
		_ = json.NewEncoder(w).Encode(response)
	}
}

func TestExchangeVerifiesTheIDTokenOfTheResponse(t *testing.T) {
	idp := newFakeIDP(t)
	issued := &issuedTokens{}
	serveTokens(t, idp, issued, true)
	client, err := NewClientFromConfig(idp.config(&recording{}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Exchange(t.Context(), oidc.Login{Nonce: "nonce-value", Verifier: "verifier-value"}, "code-value")
	if err != nil {
		t.Fatal(err)
	}
	if response.IDTokenRaw != issued.idToken || response.AccessToken != issued.accessToken {
		t.Errorf("%+v", response)
	}
}

// OpenID Connect Core section 3.1.3.3: the token response has an ID token, and without one nothing has been verified.
func TestExchangeRefusesAResponseWithoutAnIDToken(t *testing.T) {
	idp := newFakeIDP(t)
	serveTokens(t, idp, &issuedTokens{}, false)
	client, err := NewClientFromConfig(idp.config(&recording{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), oidc.Login{Nonce: "nonce-value", Verifier: "verifier-value"}, "code-value"); err == nil {
		t.Error("accepted")
	}
}

func TestExchangeFetchesTheKeysUnderTheCallersContext(t *testing.T) {
	idp := newFakeIDP(t)
	var fetched atomic.Int64
	encJWK := idp.encJWK
	idp.encJWK = func() map[string]any {
		fetched.Add(1)
		return encJWK()
	}
	serveTokens(t, idp, &issuedTokens{}, true)
	client, err := NewClientFromConfig(idp.config(&recording{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.Exchange(ctx, oidc.Login{Nonce: "nonce-value", Verifier: "verifier-value"}, "code-value"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if n := fetched.Load(); n != 0 {
		t.Errorf("%d fetches after the context ended", n)
	}
}

// challengeFlow is an IDP that challenges with claims, signed by alg, and answers the signed challenge with answer.
func challengeFlow(t *testing.T, idp *fakeIDP, alg string, claims map[string]any, answer http.HandlerFunc) *Authenticator {
	t.Helper()
	idp.authorization = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			answer(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"challenge": signIDToken(t, idp.key, alg, claims), "user_consent": map[string]any{}})
	}
	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		IDP: NewIDP(EnvironmentReference, idp.URL), SignerFunc: SignWithSoftkey(idp.key, idp.cert), Trust: &recording{}, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func validChallenge() map[string]any {
	return map[string]any{"exp": time.Now().Add(time.Minute).Unix(), "state": "state-value", "nonce": "nonce-value"}
}

func redirectTo(location string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}
}

func TestAuthenticateReturnsTheCodeOfTheRedirect(t *testing.T) {
	idp := newFakeIDP(t)
	authenticator := challengeFlow(t, idp, josebp.AlgorithmNameBP256R1, validChallenge(), redirectTo("https://rp.example/cb?code=code-value&state=state-value"))
	redirect, err := authenticator.Authenticate(idp.URL + "/auth?client_id=c")
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Code != "code-value" || redirect.State != "state-value" {
		t.Errorf("%+v", redirect)
	}
}

// As ti-idpd's challenge::code: a redirect that carries the IDP's error, or no code, is no success.
func TestAuthenticateRefusesAnAnswerThatCarriesNoCode(t *testing.T) {
	for name, tc := range map[string]struct {
		answer http.HandlerFunc
		idpErr string
	}{
		"an error in the redirect": {
			answer: redirectTo("https://rp.example/cb?error=access_denied&gematik_code=2020&gematik_error_text=nein&gematik_timestamp=1&state=s"),
			idpErr: "access_denied",
		},
		"an error beside a code": {
			answer: redirectTo("https://rp.example/cb?error=access_denied&code=code-value"),
			idpErr: "access_denied",
		},
		"a redirect without a code":     {answer: redirectTo("https://rp.example/cb?state=s")},
		"a redirect with an empty code": {answer: redirectTo("https://rp.example/cb?code=&state=s")},
		"a redirect without a Location": {answer: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusFound) }},
		"a JSON error": {
			answer: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_request","gematik_code":"2012"}`)
			},
			idpErr: "invalid_request",
		},
		"a success status": {answer: func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{}`) }},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIDP(t)
			authenticator := challengeFlow(t, idp, josebp.AlgorithmNameBP256R1, validChallenge(), tc.answer)
			redirect, err := authenticator.Authenticate(idp.URL + "/auth?client_id=c")
			if err == nil {
				t.Fatalf("success: %+v", redirect)
			}
			if tc.idpErr != "" {
				if idpErr, ok := errors.AsType[*Error](err); !ok || idpErr.ErrorCode != tc.idpErr {
					t.Errorf("err = %v", err)
				}
			}
		})
	}
}

// A challenge that is out of date gets no signature: the card holder's signature is what the flow is after.
func TestAuthenticateJudgesTheChallengeBeforeSigningIt(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		alg    string
		claims map[string]any
		accept bool
	}{
		"exp within the skew":  {josebp.AlgorithmNameBP256R1, map[string]any{"exp": now.Add(-challengeSkew / 2).Unix()}, true},
		"expired":              {josebp.AlgorithmNameBP256R1, map[string]any{"exp": now.Add(-2 * challengeSkew).Unix()}, false},
		"without exp":          {josebp.AlgorithmNameBP256R1, map[string]any{"state": "s"}, false},
		"not yet valid":        {josebp.AlgorithmNameBP256R1, map[string]any{"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(time.Hour).Unix()}, false},
		"issued in the future": {josebp.AlgorithmNameBP256R1, map[string]any{"exp": now.Add(time.Hour).Unix(), "iat": now.Add(time.Hour).Unix()}, false},
		"signed with ES256":    {"ES256", map[string]any{"exp": now.Add(time.Hour).Unix()}, false},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIDP(t)
			var posted atomic.Int64
			authenticator := challengeFlow(t, idp, tc.alg, tc.claims, func(w http.ResponseWriter, r *http.Request) {
				posted.Add(1)
				redirectTo("https://rp.example/cb?code=code-value")(w, r)
			})
			signed := false
			signer := authenticator.signerFunc
			authenticator.signerFunc = func(challenge Challenge) (string, error) {
				signed = true
				return signer(challenge)
			}
			_, err := authenticator.Authenticate(idp.URL + "/auth?client_id=c")
			if tc.accept {
				if err != nil {
					t.Errorf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Error("accepted")
			}
			if signed || posted.Load() != 0 {
				t.Errorf("signed %v, posted %d", signed, posted.Load())
			}
		})
	}
}

func TestTheIDPIsReadWithinABound(t *testing.T) {
	huge := strings.Repeat(" ", maxIDPResponseBytes+1)
	t.Run("a key", func(t *testing.T) {
		idp := newFakeIDP(t)
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, huge, `{"kty":"EC"}`)
		})
		idp.Config.Handler = mux
		if _, err := fetchKey(t.Context(), idp.URL, idp.Client()); err == nil {
			t.Error("read past the bound")
		}
	})
	t.Run("the discovery document", func(t *testing.T) {
		idp := newFakeIDP(t)
		idp.discovery = func(base string) []byte { return append([]byte(huge), idp.signDiscovery(t, base, idp.key)...) }
		_, err := NewClientFromConfig(idp.config(&recording{}))
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("an error", func(t *testing.T) {
		if err := parseErrorResponse(http.StatusBadRequest, strings.NewReader(huge+`{"error":"invalid_request"}`)); err == nil {
			t.Error("no error")
		} else if _, ok := errors.AsType[*Error](err); ok {
			t.Errorf("read past the bound: %v", err)
		}
	})
}

func TestAKeyAnswerThatIsNoSuccessIsRefused(t *testing.T) {
	idp := newFakeIDP(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(jwkOf(t, &idp.key.PublicKey, "enc"))
	})
	idp.Config.Handler = mux
	if _, err := fetchKey(t.Context(), idp.URL, idp.Client()); err == nil {
		t.Error("accepted")
	}
}

// Server rules 5 and 14: the token key, the verifier and whatever else a login holds, through a client and through an
// authenticator, whose challenge and answer carry state and nonce.
func TestALoginLogsNoSecretAtDebug(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const state, nonce, verifier, code = "state-value", "nonce-value", "verifier-value", "code-value"
	idp := newFakeIDP(t)
	issued := &issuedTokens{}
	serveTokens(t, idp, issued, true)
	client, err := NewClientFromConfig(idp.config(&recording{}))
	if err != nil {
		t.Fatal(err)
	}
	login := oidc.Login{State: state, Nonce: nonce, Verifier: verifier}
	authURL, err := client.AuthenticationURL(t.Context(), login)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), login, code); err != nil {
		t.Fatal(err)
	}

	var signedAnswer string
	authenticator := challengeFlow(t, idp, josebp.AlgorithmNameBP256R1, validChallenge(), func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		signedAnswer = r.PostForm.Get("signed_challenge")
		redirectTo("https://rp.example/cb?"+url.Values{"code": {code}, "state": {state}}.Encode())(w, r)
	})
	if _, err := authenticator.Authenticate(authURL); err != nil {
		t.Fatal(err)
	}

	authenticator = challengeFlow(t, idp, josebp.AlgorithmNameBP256R1, validChallenge(), redirectTo("https://rp.example/cb?error=access_denied&state="+state))
	idp.authorization = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_request"}`)
	}
	if _, err := authenticator.Authenticate(authURL); err == nil {
		t.Fatal("the refusal went unnoticed")
	}

	for _, value := range []string{state, nonce, verifier, code, issued.tokenKey, issued.keyVerifier, issued.accessToken, issued.idToken, issued.sealedAccessToken, issued.sealedIDToken, signedAnswer} {
		if value != "" && strings.Contains(logs.String(), value) {
			t.Errorf("the log holds %q:\n%s", value, logs.String())
		}
	}
	if issued.tokenKey == "" || signedAnswer == "" {
		t.Error("the login did not run")
	}
}

// OIDC Core 3.1.3.7, step 11: a token issued for another login must not be accepted for this one.
func TestExchangeRefusesAnIDTokenOfAnotherLogin(t *testing.T) {
	idp := newFakeIDP(t)
	serveTokens(t, idp, &issuedTokens{}, true)
	client, err := NewClientFromConfig(idp.config(&recording{}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Exchange(t.Context(), oidc.Login{Nonce: "another", Verifier: "verifier-value"}, "code-value")
	if !errors.Is(err, oidc.ErrNonceMismatch) {
		t.Fatalf("err = %v", err)
	}
}
