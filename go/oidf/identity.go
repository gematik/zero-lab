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
	// authTimeSkew is how far auth_time may lie ahead of the relying party's clock: the IDP's clock read it.
	authTimeSkew = time.Minute
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
)

// Why the ID token of a login does not make an identity.
var (
	// ErrACR is an acr that is missing, no gematik level of assurance, or lower than the lowest asked for.
	ErrACR = errors.New("acr refused")
	// ErrAMR is an amr that is missing or not a list of methods.
	ErrAMR = errors.New("amr refused")
	// ErrAuthTime is an auth_time that is missing, no time, or ahead of the clock.
	ErrAuthTime = errors.New("auth_time refused")
	// ErrEssentialClaim is a claim the login asked for as essential that the ID token lacks (gemSpec_IDP_FD A_22860-02).
	ErrEssentialClaim = errors.New("essential claim missing")
	// ErrIdentityClaim is a claim of the ID token that is not as gemSpec_IDP_Sek has it.
	ErrIdentityClaim = errors.New("identity claim refused")
)

// Identity is who logged in, as the IDP's verified ID token says; strings the token leaves out are empty. The fields
// are exported and marshal to JSON, so that a host can keep the user data it needs.
//
// Subject, ID, DisplayName, GivenName, FamilyName and Birthdate are personal data (gemSpec_IDP_FD A_23050: discarded
// once processed unless kept for a legitimate purpose). Format, String and LogValue never show them, only that they
// are withheld; they show the issuer, how and when the person authenticated, the token version, the scopes granted,
// the profession and the organization, which name a role and an insurer, not a person (servers.md rule 14).
type Identity struct {
	// Issuer is the IDP that authenticated the person.
	Issuer string `json:"issuer"`
	// Subject is sub, a pseudonym of the person for this relying party (gemSpec_IDP_Sek A_23197-01). Personal data.
	Subject string `json:"sub"`
	// ID is urn:telematik:claims:id, for insured persons the unchangeable part of the KVNR. Personal data.
	ID string `json:"id,omitempty"`
	// DisplayName, GivenName and FamilyName are the urn:telematik:claims names. Personal data.
	DisplayName string `json:"display_name,omitempty"`
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	// Birthdate is birthdate, YYYY-MM-DD as the IDP gives it. Personal data.
	Birthdate string `json:"birthdate,omitempty"`
	// Profession is urn:telematik:claims:profession, an OID naming a role: 1.2.276.0.76.4.49 for insured persons.
	Profession string `json:"profession,omitempty"`
	// Organization is urn:telematik:claims:organization, the attesting party: the insurer's IK number.
	Organization string `json:"organization,omitempty"`
	// ACR is the level of assurance of the authentication, one of the LoA constants.
	ACR string `json:"acr"`
	// AMR are the authentication methods (gemSpec_IDP_Sek A_23129-06 Tabelle 7).
	AMR      []string  `json:"amr"`
	AuthTime time.Time `json:"auth_time"`
	// IDTokenVersion is the version of the ID token's syntax, from its JWE protected header (gemSpec_IDP_Sek A_27713-01).
	IDTokenVersion string `json:"id_token_version"`
	// Scopes are the scopes granted: the token response's scope, or the scopes asked for when it names none (RFC 6749
	// section 5.1).
	Scopes []string `json:"scopes"`
}

// withheld is what the redacted forms write in place of the personal data.
const withheld = "redacted"

// String is the form Format writes: the shown fields, and personal=redacted in place of the personal data.
func (i Identity) String() string {
	return fmt.Sprintf("Identity{issuer=%s acr=%s amr=[%s] auth_time=%s id_token_version=%s scopes=[%s] profession=%s organization=%s personal=%s}",
		i.Issuer, i.ACR, strings.Join(i.AMR, " "), i.AuthTime.UTC().Format(time.RFC3339), i.IDTokenVersion,
		strings.Join(i.Scopes, " "), i.Profession, i.Organization, withheld)
}

// Format implements fmt.Formatter, so that no verb, %+v and %#v included, prints the personal data.
func (i Identity) Format(f fmt.State, verb rune) {
	if verb == 'q' {
		fmt.Fprintf(f, "%q", i.String())
		return
	}
	fmt.Fprint(f, i.String())
}

// LogValue implements slog.LogValuer with the fields String shows.
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("issuer", i.Issuer),
		slog.String("acr", i.ACR),
		slog.Any("amr", i.AMR),
		slog.String("auth_time", i.AuthTime.UTC().Format(time.RFC3339)),
		slog.String("id_token_version", i.IDTokenVersion),
		slog.Any("scopes", i.Scopes),
		slog.String("profession", i.Profession),
		slog.String("organization", i.Organization),
		slog.String("personal", withheld),
	)
}

// parseIdentity reads the identity from the payload of a verified ID token, by the claims' exact names. Every text
// claim is valid UTF-8 within maxTextBytes and free of control characters; sub, acr, amr and auth_time are required.
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
	identity.Subject = subject
	for name, target := range map[string]*string{
		claimID: &identity.ID, claimDisplayName: &identity.DisplayName, claimGivenName: &identity.GivenName,
		claimFamilyName: &identity.FamilyName, claimProfession: &identity.Profession,
		claimOrganization: &identity.Organization, claimBirthdate: &identity.Birthdate,
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
	if identity.AuthTime, err = authTimeMember(members["auth_time"]); err != nil {
		return nil, err
	}
	return identity, nil
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
	if len(raw) == 0 {
		return time.Time{}, fmt.Errorf("%w: missing", ErrAuthTime)
	}
	if err := json.Unmarshal(raw, &seconds); err != nil || seconds == nil {
		return time.Time{}, fmt.Errorf("%w: no number", ErrAuthTime)
	}
	if *seconds < 0 || *seconds > maxNumericDate {
		return time.Time{}, fmt.Errorf("%w: out of range", ErrAuthTime)
	}
	whole, fraction := math.Modf(*seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))), nil
}

// checkIdentity judges a parsed identity against its login. gemSpec_IDP_FD A_28484: the level of assurance has to be
// one of the federation's and no lower than the lowest the login asked for (OIDC Core 3.1.2.1 acr_values, ranked low <
// substantial < high), and amr names how the person authenticated; parseIdentity required a non-empty one. auth_time
// may not lie ahead of now by more than authTimeSkew. A_22860-02: each claim the login asked for as essential in the
// ID token is present, which is what the relying party knows it needs; the scopes asked for are the IDP's to grant in
// part (A_22733), and a host that needs more checks the identity itself.
func checkIdentity(identity *Identity, payload []byte, login openid.Login, now time.Time) error {
	rank, known := loaRank[identity.ACR]
	if !known {
		return fmt.Errorf("%w: not a gematik level of assurance", ErrACR)
	}
	if rank < lowestRankAsked(login.ACRValues) {
		return fmt.Errorf("%w: lower than asked for", ErrACR)
	}
	if identity.AuthTime.After(now.Add(authTimeSkew)) {
		return fmt.Errorf("%w: ahead of the clock", ErrAuthTime)
	}
	request, err := parseClaimsRequest(login.Claims)
	if err != nil {
		return err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return fmt.Errorf("%w: the payload is no JSON object", ErrIdentityClaim)
	}
	for name, essential := range request.idToken {
		if raw, ok := members[name]; essential && (!ok || string(raw) == "null") {
			return fmt.Errorf("%w: %s", ErrEssentialClaim, name)
		}
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
