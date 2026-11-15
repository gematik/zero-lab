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

package oidf

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gematik/zero-lab/go/openid"
)

const (
	// maxIDTokenPayloadBytes bounds the payload of an ID token before its claims are read.
	maxIDTokenPayloadBytes = 16 << 10
	// maxAMREntries bounds the amr claim; gemSpec_IDP_Sek Tabelle 7 has seven methods.
	maxAMREntries = 16
	// idTokenSkew is the one clock tolerance of every time claim of an ID token: exp, iat and auth_time.
	idTokenSkew = time.Minute
	// maxSignalEntries bounds urn:telematik:auth:consent.
	maxSignalEntries = 16
	// maxNumericDate is 9999-12-31T23:59:59Z, the last instant auth_time is read as, as openid reads exp.
	maxNumericDate = 253402300799
)

// The ID token claims of gemSpec_IDP_Sek A_22989-02 Tabelle 6 that an Identity carries, beside sub.
const (
	claimID           = "urn:telematik:claims:id"
	claimDisplayName  = "urn:telematik:claims:display_name"
	claimGivenName    = "urn:telematik:claims:given_name"
	claimFamilyName   = "urn:telematik:claims:family_name"
	claimProfession   = "urn:telematik:claims:profession"
	claimOrganization = "urn:telematik:claims:organization"
	claimBirthdate    = "birthdate"
	// claimConsent and claimInteractive are the signals of ID token version 2.0.0 (gemSpec_IDP_Sek A_27591, A_27592).
	claimConsent     = "urn:telematik:auth:consent"
	claimInteractive = "urn:telematik:auth:interactive"
)

// Why the ID token of a login does not make an identity.
var (
	// ErrACR is an acr that is missing, no gematik level of assurance, or lower than the lowest asked for.
	ErrACR = errors.New("acr refused")
	// ErrAMR is an amr that is missing or not a list of methods.
	ErrAMR = errors.New("amr refused")
	// ErrAuthTime is an auth_time that is missing where it was asked for, no time, or ahead of the clock.
	ErrAuthTime = errors.New("auth_time refused")
	// ErrEssentialClaim is a claim the login asked for as essential that the ID token lacks (gemSpec_IDP_FD A_22860-02).
	ErrEssentialClaim = errors.New("essential claim missing")
	// ErrIdentityClaim is a claim of the ID token that is not as gemSpec_IDP_Sek has it.
	ErrIdentityClaim = errors.New("identity claim refused")
	// ErrAuthorizedParty is an ID token for several audiences without azp, or whose azp is another client (OIDC
	// Core 3.1.3.7 steps 4 and 5).
	ErrAuthorizedParty = errors.New("azp refused")
)

// Identity is who logged in, as the IDP's verified ID token says; strings the token leaves out are empty. The fields
// are exported and marshal to JSON unredacted, so that a host can keep the user data it needs.
//
// The personal data, the claims that identify the person, are in Personal (gemSpec_IDP_FD A_23050: discarded once
// processed unless kept for a legitimate purpose). Format, String and LogValue of Identity and of Personal never show
// them, also with an Identity in a map, a slice or an exported field of a host's struct; they show the issuer, how and
// when the person authenticated, the token version and its signals, the scopes granted, the profession and the
// organization, which name a role and an insurer, not a person (servers.md rule 14). json.Marshal is not redacted,
// nor is an Identity in an unexported field, which fmt prints without its methods: a host that logs JSON or such a
// struct must not log these types.
//
// A login that asks for "high substantial" takes substantial with or without the person's consent to it for data of
// high protection need; the host decides by Consent (version 2.0.0, A_27591) or by amr urn:telematik:auth:mEW (version
// 1.0.0, A_22867-01).
type Identity struct {
	// Issuer is the IDP that authenticated the person.
	Issuer string `json:"issuer"`
	// Personal holds the claims that identify the person.
	Personal Personal `json:"personal"`
	// Profession is urn:telematik:claims:profession, an OID naming a role: 1.2.276.0.76.4.49 for insured persons.
	Profession string `json:"profession,omitempty"`
	// Organization is urn:telematik:claims:organization, the attesting party: the insurer's IK number.
	Organization string `json:"organization,omitempty"`
	// ACR is the level of assurance of the authentication, one of the LoA constants.
	ACR string `json:"acr"`
	// AMR are the authentication methods (gemSpec_IDP_Sek A_23129-06 Tabelle 7).
	AMR []string `json:"amr"`
	// AuthTime is auth_time, zero when the token does not state it.
	AuthTime time.Time `json:"auth_time,omitzero"`
	// IDTokenVersion is the version of the ID token's syntax, from its JWE protected header (gemSpec_IDP_Sek A_27713-01).
	IDTokenVersion string `json:"id_token_version"`
	// Consent is urn:telematik:auth:consent: loa-substantial when the person consented to substantial for data of high
	// protection need (A_27591).
	Consent []string `json:"consent,omitempty"`
	// Interactive is urn:telematik:auth:interactive: silent for single sign-on without interaction (A_27592).
	Interactive string `json:"interactive,omitempty"`
	// Scopes are the scopes granted: the token response's scope, or the scopes asked for when it names none (RFC 6749
	// section 5.1).
	Scopes []string `json:"scopes"`
}

// Personal are the claims of an ID token that identify the person (gemSpec_IDP_Sek A_22989-02 Tabelle 6). Its
// Format, String and LogValue show none of them, only that they are withheld; json.Marshal shows them all.
type Personal struct {
	// Subject is sub, a pseudonym of the person for this relying party (gemSpec_IDP_Sek A_23197-01).
	Subject string `json:"sub"`
	// ID is urn:telematik:claims:id, for insured persons the unchangeable part of the KVNR.
	ID string `json:"id,omitempty"`
	// DisplayName, GivenName and FamilyName are the urn:telematik:claims names.
	DisplayName string `json:"display_name,omitempty"`
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	// Birthdate is birthdate, YYYY-MM-DD as the IDP gives it.
	Birthdate string `json:"birthdate,omitempty"`
}

// withheld is what the redacted forms write in place of the personal data.
const withheld = "redacted"

// String is the form Format writes.
func (Personal) String() string {
	return withheld
}

// Format implements fmt.Formatter, so that no verb, %+v and %#v included, prints the personal data.
func (p Personal) Format(f fmt.State, verb rune) {
	formatRedacted(f, verb, p.String())
}

// LogValue implements slog.LogValuer.
func (Personal) LogValue() slog.Value {
	return slog.StringValue(withheld)
}

// String is the form Format writes: the shown fields, and personal=redacted in place of the personal data.
func (i Identity) String() string {
	return fmt.Sprintf("Identity{issuer=%s acr=%s amr=[%s] auth_time=%s id_token_version=%s consent=[%s] interactive=%s scopes=[%s] profession=%s organization=%s personal=%s}",
		i.Issuer, i.ACR, strings.Join(i.AMR, " "), i.authTime(), i.IDTokenVersion, strings.Join(i.Consent, " "),
		i.Interactive, strings.Join(i.Scopes, " "), i.Profession, i.Organization, withheld)
}

// Format implements fmt.Formatter, so that no verb, %+v and %#v included, prints the personal data.
func (i Identity) Format(f fmt.State, verb rune) {
	formatRedacted(f, verb, i.String())
}

// formatRedacted writes the redacted form for any verb, quoted for %q.
func formatRedacted(f fmt.State, verb rune, redacted string) {
	if verb == 'q' {
		fmt.Fprintf(f, "%q", redacted)
		return
	}
	fmt.Fprint(f, redacted)
}

// LogValue implements slog.LogValuer with the fields String shows.
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("issuer", i.Issuer),
		slog.String("acr", i.ACR),
		slog.Any("amr", i.AMR),
		slog.String("auth_time", i.authTime()),
		slog.String("id_token_version", i.IDTokenVersion),
		slog.Any("consent", i.Consent),
		slog.String("interactive", i.Interactive),
		slog.Any("scopes", i.Scopes),
		slog.String("profession", i.Profession),
		slog.String("organization", i.Organization),
		slog.String("personal", withheld),
	)
}

// authTime is auth_time in RFC 3339, empty when the token does not state it.
func (i Identity) authTime() string {
	if i.AuthTime.IsZero() {
		return ""
	}
	return i.AuthTime.UTC().Format(time.RFC3339)
}

// parseIdentity reads the identity from the payload of a verified ID token, by the claims' exact names. Every text
// claim is valid UTF-8 within maxTextBytes and free of control and format characters; sub, acr and amr are required.
// It judges no level of assurance and no time; checkIdentity does.
func parseIdentity(payload []byte, issuer, version string) (*Identity, error) {
	if len(payload) > maxIDTokenPayloadBytes {
		return nil, fmt.Errorf("%w: the payload is larger than %d bytes", ErrIdentityClaim, maxIDTokenPayloadBytes)
	}
	if !utf8.Valid(payload) {
		return nil, fmt.Errorf("%w: the payload is not UTF-8", ErrIdentityClaim)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: the payload is no JSON object", ErrIdentityClaim)
	}
	identity := &Identity{Issuer: issuer, IDTokenVersion: version}
	subject, present, err := textMember(members, "sub", maxTextBytes)
	if err != nil || !present || subject == "" {
		return nil, fmt.Errorf("%w: sub", ErrIdentityClaim)
	}
	identity.Personal.Subject = subject
	for name, target := range map[string]*string{
		claimID: &identity.Personal.ID, claimDisplayName: &identity.Personal.DisplayName,
		claimGivenName: &identity.Personal.GivenName, claimFamilyName: &identity.Personal.FamilyName,
		claimBirthdate: &identity.Personal.Birthdate, claimProfession: &identity.Profession,
		claimOrganization: &identity.Organization,
	} {
		if *target, _, err = textMember(members, name, maxTextBytes); err != nil {
			return nil, fmt.Errorf("%w: %s %w", ErrIdentityClaim, name, err)
		}
	}
	if identity.ACR, present, err = textMember(members, "acr", maxTextBytes); err != nil || !present {
		return nil, fmt.Errorf("%w: missing or no text", ErrACR)
	}
	if identity.AMR, err = amrMember(members["amr"]); err != nil {
		return nil, err
	}
	if raw, ok := members["auth_time"]; ok {
		if identity.AuthTime, err = authTimeMember(raw); err != nil {
			return nil, err
		}
	}
	if identity.Consent, err = signalMember(members[claimConsent], maxSignalEntries); err != nil {
		return nil, fmt.Errorf("%w: %s %w", ErrIdentityClaim, claimConsent, err)
	}
	interactive, err := signalMember(members[claimInteractive], 1)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %w", ErrIdentityClaim, claimInteractive, err)
	}
	if len(interactive) == 1 {
		identity.Interactive = interactive[0]
	}
	return identity, nil
}

// signalMember reads a custom claim of version 2.0.0. gemSpec_IDP_Sek gives the values ("den Wert loa-substantial
// ergänzen", "auf den Wert silent gesetzt") but no JSON type, so a string or an array of at most most strings is taken,
// and nothing else.
func signalMember(raw json.RawMessage, most int) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if err := checkText(single, maxTextBytes); err != nil || single == "" {
			return nil, errors.New("is no text")
		}
		return []string{single}, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil || list == nil {
		return nil, errors.New("is neither text nor a list of text")
	}
	if len(list) > most {
		return nil, fmt.Errorf("has more than %d values", most)
	}
	values := make([]string, 0, len(list))
	for _, entry := range list {
		var value string
		if err := json.Unmarshal(entry, &value); err != nil || value == "" || checkText(value, maxTextBytes) != nil {
			return nil, errors.New("holds a value that is no text")
		}
		values = append(values, value)
	}
	return values, nil
}

// amrMember reads amr, a JSON array of strings (OIDC Core 2), of at least one and at most maxAMREntries methods.
func amrMember(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: missing", ErrAMR)
	}
	var methods []json.RawMessage
	if err := json.Unmarshal(raw, &methods); err != nil || len(methods) == 0 {
		return nil, fmt.Errorf("%w: no array of methods", ErrAMR)
	}
	if len(methods) > maxAMREntries {
		return nil, fmt.Errorf("%w: more than %d methods", ErrAMR, maxAMREntries)
	}
	amr := make([]string, 0, len(methods))
	for _, method := range methods {
		var value string
		if err := json.Unmarshal(method, &value); err != nil {
			return nil, fmt.Errorf("%w: a method is no text", ErrAMR)
		}
		if err := checkText(value, maxTextBytes); err != nil || value == "" {
			return nil, fmt.Errorf("%w: a method is no text", ErrAMR)
		}
		amr = append(amr, value)
	}
	return amr, nil
}

// authTimeMember reads auth_time, a NumericDate (OIDC Core 2), as openid reads exp.
func authTimeMember(raw json.RawMessage) (time.Time, error) {
	var seconds *float64
	if err := json.Unmarshal(raw, &seconds); err != nil || seconds == nil {
		return time.Time{}, fmt.Errorf("%w: no number", ErrAuthTime)
	}
	if *seconds < 0 || *seconds > maxNumericDate {
		return time.Time{}, fmt.Errorf("%w: out of range", ErrAuthTime)
	}
	whole, fraction := math.Modf(*seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))), nil
}

// checkIdentity judges a parsed identity against its login and the client it was issued to.
//   - gemSpec_IDP_FD A_28484: the level of assurance is one of the federation's and no lower than the lowest the login
//     asked for (OIDC Core 3.1.2.1 acr_values, ranked low < substantial < high); amr names how the person
//     authenticated, which parseIdentity required. Substantial is refused when only high was asked for, with or
//     without consent, in both token versions.
//   - OIDC Core 3.1.3.7: iat is present; with several audiences azp is present, and an azp names this client.
//   - OIDC Core 2 and 5.5: auth_time is required when the login's claims request asks for it (or max_age, which a
//     login does not send); when present it may not lie ahead of now by more than idTokenSkew.
//   - A_22860-02: each claim the login asked for as essential in the ID token is present, which is what the relying
//     party knows it needs; the scopes asked for are the IDP's to grant in part (A_22733), and a host that needs more
//     checks the identity itself.
func checkIdentity(identity *Identity, payload []byte, login openid.Login, clientID string, now time.Time) error {
	rank, known := loaRank[identity.ACR]
	if !known {
		return fmt.Errorf("%w: not a gematik level of assurance", ErrACR)
	}
	if rank < lowestRankAsked(login.ACRValues) {
		return fmt.Errorf("%w: lower than asked for", ErrACR)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return fmt.Errorf("%w: the payload is no JSON object", ErrIdentityClaim)
	}
	if raw, ok := members["iat"]; !ok || string(raw) == "null" {
		return fmt.Errorf("%w: iat", openid.ErrMissingClaim)
	}
	if err := checkAuthorizedParty(members, clientID); err != nil {
		return err
	}
	request, err := parseClaimsRequest(login.Claims)
	if err != nil {
		return err
	}
	if _, asked := request.idToken["auth_time"]; asked && identity.AuthTime.IsZero() {
		return fmt.Errorf("%w: missing although asked for", ErrAuthTime)
	}
	if identity.AuthTime.After(now.Add(idTokenSkew)) {
		return fmt.Errorf("%w: ahead of the clock", ErrAuthTime)
	}
	for name, essential := range request.idToken {
		if raw, ok := members[name]; essential && (!ok || string(raw) == "null") {
			return fmt.Errorf("%w: %s", ErrEssentialClaim, name)
		}
	}
	return nil
}

// checkAuthorizedParty holds azp to OIDC Core 3.1.3.7 steps 4 and 5. openid's checks have read aud as a string or an
// array of strings already.
func checkAuthorizedParty(members map[string]json.RawMessage, clientID string) error {
	var audiences []string
	if err := json.Unmarshal(members["aud"], &audiences); err != nil {
		audiences = nil
	}
	azp, present, err := textMember(members, "azp", maxTextBytes)
	switch {
	case err != nil:
		return fmt.Errorf("%w: no text", ErrAuthorizedParty)
	case !present && len(audiences) > 1:
		return fmt.Errorf("%w: missing with several audiences", ErrAuthorizedParty)
	case present && azp != clientID:
		return fmt.Errorf("%w: another client", ErrAuthorizedParty)
	}
	return nil
}

// lowestRankAsked is the rank of the lowest level a login asked for; no acr_values ask for gematik-ehealth-loa-high.
func lowestRankAsked(acrValues []string) int {
	if len(acrValues) == 0 {
		return loaRank[LoAHigh]
	}
	lowest := loaRank[LoAHigh]
	for _, acr := range acrValues {
		if rank, known := loaRank[acr]; known && rank < lowest {
			lowest = rank
		}
	}
	return lowest
}
