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

package pep

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/gematik/zero-lab/go/dpop"
)

// EnforcerType names the kind of an Enforcer; it is the "type" member of the JSON form.
type EnforcerType string

// The kinds of Enforcer. EnforcerTypeCustom marks one made by EnforcerFromFunc; the others are the JSON forms
// EnforcerHolder decodes.
const (
	EnforcerTypeCustom              EnforcerType = "Custom"
	EnforcerTypeAllOf               EnforcerType = "AllOf"
	EnforcerTypeAnyOf               EnforcerType = "AnyOf"
	EnforcerTypeDeny                EnforcerType = "Deny"
	EnforcerTypeAuthorizationBearer EnforcerType = "AuthorizationBearer"
	EnforcerTypeAuthorizationDPoP   EnforcerType = "AuthorizationDPoP"
	EnforcerTypeScope               EnforcerType = "Scope"
	EnforcerTypeSessionCookie       EnforcerType = "SessionCookie"
)

// Enforcer decides on one request: Apply either calls next to let it through or denies it through
// ctx.Deny, and the combinators rely on it never doing both.
type Enforcer interface {
	Type() EnforcerType
	Apply(ctx Context, next HandlerFunc)
}

// MultipleEnforcer is implemented by the enforcers composed of others, so configuration code can add to them.
type MultipleEnforcer interface {
	Enforcers() []Enforcer
	Append(Enforcer)
}

// EnforcerHolder gives an Enforcer its JSON form: the "type" member selects the concrete type on decoding.
type EnforcerHolder struct {
	Enforcer
}

// UnmarshalJSON decodes the enforcer named by "type" and fails on an unknown type, so a misspelled
// policy cannot load; EnforcerTypeCustom has no JSON form and is unknown here.
func (h *EnforcerHolder) UnmarshalJSON(data []byte) error {
	r := struct {
		Type EnforcerType `json:"type"`
	}{}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	switch r.Type {
	case EnforcerTypeAllOf:
		h.Enforcer = &EnforcerAllOf{}
	case EnforcerTypeAnyOf:
		h.Enforcer = &EnforcerAnyOf{}
	case EnforcerTypeDeny:
		h.Enforcer = &EnforcerDeny{}
	case EnforcerTypeAuthorizationBearer:
		h.Enforcer = &EnforcerAuthorizationBearer{}
	case EnforcerTypeAuthorizationDPoP:
		h.Enforcer = &EnforcerAuthorizationDPoP{}
	case EnforcerTypeScope:
		h.Enforcer = &EnforcerScope{}
	case EnforcerTypeSessionCookie:
		h.Enforcer = &EnforcerSessionCookie{}
	default:
		return fmt.Errorf("unknown enforcer type: %s", r.Type)
	}
	return json.Unmarshal(data, h.Enforcer)
}

// MarshalJSON writes the held enforcer's own JSON form.
func (h EnforcerHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.Enforcer)
}

// EnforcerAllOf lets a request through when every enforcer allows it; an empty list denies.
type EnforcerAllOf struct {
	TypeVal         EnforcerType     `json:"type"`
	EnforcerHolders []EnforcerHolder `json:"enforcers"`
}

// Type returns EnforcerTypeAllOf.
func (e EnforcerAllOf) Type() EnforcerType {
	return EnforcerTypeAllOf
}

// Apply stops at the first denial and passes it on; the enforcers share one context, so a later one
// sees the claims an earlier one set.
func (e EnforcerAllOf) Apply(ctx Context, next HandlerFunc) {
	if len(e.EnforcerHolders) == 0 {
		slog.Warn("No enforcers confgured, denying request")
		ctx.Deny(ErrorAccessDeinied("No enforcers configured"))
		return
	}
	var errorFromGuard *Error

	singleNext := func(_ Context) {}

	singleDeny := func(_ Context, err Error) {
		errorFromGuard = &err
	}

	subCtx := ctx.WithDeny(singleDeny)

	for _, enforcer := range e.EnforcerHolders {
		slog.Debug("Applying enforcer", "type", enforcer.Type())
		enforcer.Apply(subCtx, singleNext)
		if errorFromGuard != nil {
			ctx.Deny(*errorFromGuard)
			return
		}
	}

	next(ctx)
}

// Enforcers returns the held enforcers in evaluation order.
func (e EnforcerAllOf) Enforcers() []Enforcer {
	enforcers := make([]Enforcer, len(e.EnforcerHolders))
	for i, enforcer := range e.EnforcerHolders {
		enforcers[i] = enforcer.Enforcer
	}
	return enforcers
}

// Append adds an enforcer to be evaluated last.
func (e *EnforcerAllOf) Append(enforcer Enforcer) {
	e.EnforcerHolders = append(e.EnforcerHolders, EnforcerHolder{enforcer})
}

// EnforcerAnyOf lets a request through when at least one enforcer allows it; an empty list denies.
type EnforcerAnyOf struct {
	TypeVal         EnforcerType     `json:"type"`
	EnforcerHolders []EnforcerHolder `json:"enforcers"`
}

// Type returns EnforcerTypeAnyOf.
func (e EnforcerAnyOf) Type() EnforcerType {
	return EnforcerTypeAnyOf
}

// Apply stops at the first enforcer that allows; when none does the request is denied with
// access_denied, not with the denial of any single enforcer.
func (e EnforcerAnyOf) Apply(ctx Context, next HandlerFunc) {
	if len(e.EnforcerHolders) == 0 {
		slog.Warn("No enforcers confgured, denying request")
		ctx.Deny(ErrorAccessDeinied("No enforcers configured"))
		return
	}
	var errorFromGuard *Error

	singleNext := func(_ Context) {}

	singleDeny := func(_ Context, err Error) {
		errorFromGuard = &err
	}

	subCtx := ctx.WithDeny(singleDeny)

	for _, enforcer := range e.EnforcerHolders {
		slog.Debug("Applying enforcer", "type", enforcer.Type())
		enforcer.Apply(subCtx, singleNext)
		if errorFromGuard == nil {
			next(ctx)
			return
		}
		errorFromGuard = nil
	}

	ctx.Deny(ErrorAccessDeinied("None of the enforcers in any_of allowed the request"))
}

// Enforcers returns the held enforcers in evaluation order.
func (e EnforcerAnyOf) Enforcers() []Enforcer {
	enforcers := make([]Enforcer, len(e.EnforcerHolders))
	for i, enforcer := range e.EnforcerHolders {
		enforcers[i] = enforcer.Enforcer
	}
	return enforcers
}

// Append adds an enforcer to be evaluated last.
func (e *EnforcerAnyOf) Append(enforcer Enforcer) {
	e.EnforcerHolders = append(e.EnforcerHolders, EnforcerHolder{enforcer})
}

// EnforcerDeny refuses every request, for routes a policy closes by configuration.
type EnforcerDeny struct {
	TypeVal EnforcerType `json:"type"`
}

// Type returns EnforcerTypeDeny.
func (e *EnforcerDeny) Type() EnforcerType {
	return EnforcerTypeDeny
}

// Apply denies with access_denied and never calls next.
func (e *EnforcerDeny) Apply(ctx Context, _ HandlerFunc) {
	ctx.Deny(ErrorAccessDeinied("Access denied by configuration"))
}

// EnforcerScope requires one scope in the "scope" claim, a space-separated list. It reads the claims a
// previous enforcer set, so it follows a token or session enforcer in an EnforcerAllOf.
type EnforcerScope struct {
	TypeVal EnforcerType `json:"type"`
	Scope   string       `json:"scope"`
}

// Type returns EnforcerTypeScope.
func (e *EnforcerScope) Type() EnforcerType {
	return EnforcerTypeScope
}

// Apply denies with access_denied when the claims are missing or lack the scope.
func (e *EnforcerScope) Apply(ctx Context, next HandlerFunc) {
	scopeStruct := struct {
		Scope string `json:"scope"`
	}{}
	if err := ctx.UnmarshalClaims(&scopeStruct); err != nil {
		ctx.Slogger().Error("Failed to get claims", "error", err)
		ctx.Deny(ErrorAccessDeinied("Claims not available"))
		return
	}

	scopes := strings.Split(scopeStruct.Scope, " ")
	if slices.Contains(scopes, e.Scope) {
		next(ctx)
		return
	}

	ctx.Slogger().Warn("Scope not found in claims", "required", e.Scope, "actual", scopes)

	ctx.Deny(ErrorAccessDeinied("Scope not found in claims"))
}

// EnforcerSessionCookie is implemented in session_cookie.go (the stateless snapshot gate).

type enforcerFunc struct {
	apply func(Context, HandlerFunc)
}

func (e *enforcerFunc) Type() EnforcerType {
	return EnforcerTypeCustom
}

func (e *enforcerFunc) Apply(ctx Context, next HandlerFunc) {
	e.apply(ctx, next)
}

// EnforcerFromFunc makes an Enforcer of type EnforcerTypeCustom from a function; apply has to keep the
// contract of Enforcer. Such an enforcer cannot be decoded by EnforcerHolder.
func EnforcerFromFunc(apply func(Context, HandlerFunc)) Enforcer {
	return &enforcerFunc{apply}
}

// EnforcerAuthorizationBearer requires a valid JWT access token in a Bearer Authorization header
// (RFC 6750) and makes its claims available on the context.
type EnforcerAuthorizationBearer struct {
	TypeVal EnforcerType `json:"type"`
}

// Type returns EnforcerTypeAuthorizationBearer.
func (e *EnforcerAuthorizationBearer) Type() EnforcerType {
	return EnforcerTypeAuthorizationBearer
}

// Apply needs the Context of PEP.NewContext, because the keys it verifies with live on the PEP; any other
// Context is denied with internal_error.
func (e *EnforcerAuthorizationBearer) Apply(ctx Context, next HandlerFunc) {
	internalCtx, ok := ctx.(*pepContext)
	if !ok {
		ctx.Slogger().Error("Failed to cast context to pepContext")
		ctx.Deny(Error{HTTPStatus: 500, Code: "internal_error", Description: "Failed to cast context to pepContext"})
		return
	}

	if err := internalCtx.verifyAuthorizationBearer(); err != nil {
		ctx.Slogger().Warn("Failed to verify authorization bearer", "error", err)
		if pepErr, ok := errors.AsType[Error](err); ok {
			ctx.Deny(pepErr)
		} else {
			ctx.Deny(ErrorAccessDeinied("Failed to verify authorization bearer"))
		}
		return
	}
	ctx.Slogger().Debug("Authorization bearer successfully verified")
	next(ctx)
}

// EnforcerAuthorizationDPoP requires a DPoP-bound JWT access token and its proof (RFC 9449 Section 7.1)
// and makes the token's claims available on the context. NonceRequired is not implemented: when set,
// every request is denied with internal_error.
type EnforcerAuthorizationDPoP struct {
	TypeVal       EnforcerType `json:"type"`
	NonceRequired bool         `json:"nonce_required"`
}

// Type returns EnforcerTypeAuthorizationDPoP.
func (e *EnforcerAuthorizationDPoP) Type() EnforcerType {
	return EnforcerTypeAuthorizationDPoP
}

// Apply needs the Context of PEP.NewContext, because the keys and the public origin it verifies with live
// on the PEP; any other Context is denied with internal_error.
func (e *EnforcerAuthorizationDPoP) Apply(ctx Context, next HandlerFunc) {
	internalCtx, ok := ctx.(*pepContext)
	if !ok {
		ctx.Slogger().Error("Failed to cast context to pepContext")
		ctx.Deny(Error{
			HTTPStatus:  500,
			Code:        "internal_error",
			Description: "Failed to cast context to pepContext",
		})
		return
	}

	// Resource server nonces (RFC 9449 Section 9) need a NonceSource shared by the replicas,
	// which pep does not have yet: refusing beats checking proofs without the nonce.
	if e.NonceRequired {
		ctx.Deny(Error{
			HTTPStatus:  500,
			Code:        "internal_error",
			Description: "Nonce required but not implemented",
		})
		return
	}

	if err := internalCtx.verifyAuthorizationDPoP(); err != nil {
		ctx.Slogger().Warn("Failed to verify authorization dpop", "error", err)
		var pepErr Error
		var dpopErr *dpop.Error
		switch {
		case errors.As(err, &pepErr):
			ctx.Deny(pepErr)
		case errors.As(err, &dpopErr):
			ctx.Deny(internalCtx.pep.dpopDenial(dpopErr))
		default:
			ctx.Deny(Error{
				HTTPStatus:  http.StatusInternalServerError,
				Code:        "internal_error",
				Description: "DPoP could not be checked",
			})
		}
		return
	}

	ctx.Slogger().Debug("Authorization dpop successfully verified")
	next(ctx)
}
