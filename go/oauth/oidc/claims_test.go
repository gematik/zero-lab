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

package oidc

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestIDTokenChecks(t *testing.T) {
	const (
		issuer   = "https://op.example"
		clientID = "client"
		skew     = time.Minute
	)
	now := time.Unix(1_700_000_000, 0)
	at := func(offset time.Duration) int64 { return now.Add(offset).Unix() }
	valid := fmt.Sprintf(`"iss":%q,"aud":%q,"nonce":"n","exp":%d`, issuer, clientID, at(time.Hour))

	for _, tc := range []struct {
		name    string
		payload string
		want    error
	}{
		{"a complete token passes", `{` + valid + `}`, nil},
		{"aud may be a list naming the client", fmt.Sprintf(`{"iss":%q,"aud":["other",%q],"nonce":"n","exp":%d}`, issuer, clientID, at(time.Hour)), nil},
		{"another issuer is refused", fmt.Sprintf(`{"iss":"https://evil.example","aud":%q,"nonce":"n","exp":%d}`, clientID, at(time.Hour)), ErrIssuerMismatch},
		{"a missing issuer is refused", fmt.Sprintf(`{"aud":%q,"nonce":"n","exp":%d}`, clientID, at(time.Hour)), ErrIssuerMismatch},
		{"another audience is refused", fmt.Sprintf(`{"iss":%q,"aud":"other","nonce":"n","exp":%d}`, issuer, at(time.Hour)), ErrAudienceMismatch},
		{"a list without the client is refused", fmt.Sprintf(`{"iss":%q,"aud":["a","b"],"nonce":"n","exp":%d}`, issuer, at(time.Hour)), ErrAudienceMismatch},
		{"a missing audience is refused", fmt.Sprintf(`{"iss":%q,"nonce":"n","exp":%d}`, issuer, at(time.Hour)), ErrMissingClaim},
		{"a missing nonce is refused", fmt.Sprintf(`{"iss":%q,"aud":%q,"exp":%d}`, issuer, clientID, at(time.Hour)), ErrMissingClaim},
		{"an empty nonce is refused", fmt.Sprintf(`{"iss":%q,"aud":%q,"nonce":"","exp":%d}`, issuer, clientID, at(time.Hour)), ErrMissingClaim},
		{"a missing exp is refused", fmt.Sprintf(`{"iss":%q,"aud":%q,"nonce":"n"}`, issuer, clientID), ErrMissingClaim},
		{"exp just inside the skew passes", fmt.Sprintf(`{"iss":%q,"aud":%q,"nonce":"n","exp":%d}`, issuer, clientID, at(-skew+time.Second)), nil},
		{"exp at the end of the skew is refused", fmt.Sprintf(`{"iss":%q,"aud":%q,"nonce":"n","exp":%d}`, issuer, clientID, at(-skew)), ErrTokenExpired},
		{"nbf at the end of the skew passes", `{` + valid + fmt.Sprintf(`,"nbf":%d}`, at(skew)), nil},
		{"nbf past the skew is refused", `{` + valid + fmt.Sprintf(`,"nbf":%d}`, at(skew+time.Second)), ErrTokenNotYetValid},
		{"iat at the end of the skew passes", `{` + valid + fmt.Sprintf(`,"iat":%d}`, at(skew)), nil},
		{"iat past the skew is refused", `{` + valid + fmt.Sprintf(`,"iat":%d}`, at(skew+time.Second)), ErrTokenIssuedInFuture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := IDTokenChecks{Nonce: "n", Issuer: issuer, ClientID: clientID, Now: now, Skew: skew}.Validate([]byte(tc.payload))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIDTokenChecksWithAnEmptyExpectationRefuseEverything(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	payload := fmt.Sprintf(`{"iss":"","aud":"","nonce":"n","exp":%d}`, now.Add(time.Hour).Unix())
	if err := (IDTokenChecks{Nonce: "n", ClientID: "c", Now: now}).Validate([]byte(payload)); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("empty issuer: %v", err)
	}
	if err := (IDTokenChecks{Nonce: "n", Issuer: "i", Now: now}).Validate([]byte(fmt.Sprintf(`{"iss":"i","aud":"","nonce":"n","exp":%d}`, now.Add(time.Hour).Unix()))); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("empty client: %v", err)
	}
}

func TestClaimNamesAreCaseSensitive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	payload := fmt.Sprintf(`{"ISS":"i","AUD":"c","NONCE":"n","EXP":%d}`, now.Add(time.Hour).Unix())
	if err := (IDTokenChecks{Nonce: "n", Issuer: "i", ClientID: "c", Now: now}).Validate([]byte(payload)); err == nil {
		t.Error("took upper-case members for the registered claims")
	}
}

func TestClaimsOfTheWrongTypeAreRefused(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, payload := range []string{
		`null`, `[]`, `"x"`, `not json`,
		`{"iss":1}`, `{"iss":null}`, `{"sub":1}`, `{"jti":1}`, `{"nonce":1}`,
		`{"aud":1}`, `{"aud":null}`, `{"aud":[1]}`, `{"aud":[null]}`,
		`{"exp":"1700003600"}`, `{"exp":null}`, `{"exp":true}`, `{"nbf":{}}`, `{"iat":[]}`, `{"exp":1e300}`, `{"exp":-1e300}`,
	} {
		if err := ValidateLifetime([]byte(payload), now, 0); err == nil {
			t.Errorf("accepted %s", payload)
		}
	}
}

func TestValidateLifetimeAllowsAbsentTimeClaims(t *testing.T) {
	if err := ValidateLifetime([]byte(`{"iss":"i"}`), time.Now(), 0); err != nil {
		t.Error(err)
	}
}

func TestValidateLifetimeRefusesAtTheInstantOfExp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if err := ValidateLifetime(fmt.Appendf(nil, `{"exp":%d}`, now.Unix()), now, 0); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("err = %v", err)
	}
	if err := ValidateLifetime(fmt.Appendf(nil, `{"exp":%d}`, now.Unix()), now.Add(-time.Nanosecond), 0); err != nil {
		t.Errorf("before exp: %v", err)
	}
}

func TestValidateLifetimeKeepsFractionalSeconds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if err := ValidateLifetime(fmt.Appendf(nil, `{"nbf":%d.5}`, now.Unix()), now, 0); !errors.Is(err, ErrTokenNotYetValid) {
		t.Errorf("nbf half a second ahead: %v", err)
	}
	if err := ValidateLifetime(fmt.Appendf(nil, `{"exp":%d.5}`, now.Unix()), now, 0); err != nil {
		t.Errorf("exp half a second ahead: %v", err)
	}
}

func TestValidateAudience(t *testing.T) {
	if err := ValidateAudience([]byte(`{"aud":["a","c"]}`), "c"); err != nil {
		t.Error(err)
	}
	if err := ValidateAudience([]byte(`{"aud":"a"}`), "c"); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("err = %v", err)
	}
	if err := ValidateAudience([]byte(`{}`), "c"); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("err = %v", err)
	}
}

func TestIDTokenChecksBindTheTokenToTheLogin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	payload := fmt.Appendf(nil, `{"iss":"i","aud":"c","nonce":"n","exp":%d}`, now.Add(time.Hour).Unix())
	for name, expected := range map[string]string{"another login": "other", "no nonce expected": ""} {
		checks := IDTokenChecks{Issuer: "i", ClientID: "c", Nonce: expected, Now: now}
		if err := checks.Validate(payload); !errors.Is(err, ErrNonceMismatch) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
