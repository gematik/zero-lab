package pep

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gematik/zero-lab/go/dpop"
)

type EnforcerType string

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

type Enforcer interface {
	Type() EnforcerType
	Apply(ctx Context, next HandlerFunc)
}

type MultipleEnforcer interface {
	Enforcers() []Enforcer
	Append(Enforcer)
}

type EnforcerHolder struct {
	Enforcer
}

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

func (h EnforcerHolder) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.Enforcer)
}

type EnforcerAllOf struct {
	TypeVal         EnforcerType     `json:"type" validate:"required"`
	EnforcerHolders []EnforcerHolder `json:"enforcers" validate:"required,dive"`
}

func (e EnforcerAllOf) Type() EnforcerType {
	return EnforcerTypeAllOf
}

func (e EnforcerAllOf) Apply(ctx Context, next HandlerFunc) {
	if len(e.EnforcerHolders) == 0 {
		slog.Warn("No enforcers confgured, denying request")
		ctx.Deny(ErrorAccessDeinied("No enforcers configured"))
		return
	}
	var errorFromGuard *Error

	singleNext := func(ctx Context) {}

	singleDeny := func(ctx Context, err Error) {
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

func (e EnforcerAllOf) Enforcers() []Enforcer {
	enforcers := make([]Enforcer, len(e.EnforcerHolders))
	for i, enforcer := range e.EnforcerHolders {
		enforcers[i] = enforcer.Enforcer
	}
	return enforcers
}

func (e *EnforcerAllOf) Append(enforcer Enforcer) {
	e.EnforcerHolders = append(e.EnforcerHolders, EnforcerHolder{enforcer})
}

type EnforcerAnyOf struct {
	TypeVal         EnforcerType     `json:"type" validate:"required"`
	EnforcerHolders []EnforcerHolder `json:"enforcers" validate:"required,dive"`
}

func (e EnforcerAnyOf) Type() EnforcerType {
	return EnforcerTypeAnyOf
}

func (e EnforcerAnyOf) Apply(ctx Context, next HandlerFunc) {
	if len(e.EnforcerHolders) == 0 {
		slog.Warn("No enforcers confgured, denying request")
		ctx.Deny(ErrorAccessDeinied("No enforcers configured"))
		return
	}
	var errorFromGuard *Error

	singleNext := func(ctx Context) {}

	singleDeny := func(ctx Context, err Error) {
		errorFromGuard = &err
	}

	subCtx := ctx.WithDeny(singleDeny)

	for _, enforcer := range e.EnforcerHolders {
		slog.Debug("Applying enforcer", "type", enforcer.Type())
		enforcer.Apply(subCtx, singleNext)
		if errorFromGuard == nil {
			next(ctx)
			return
		} else {
			errorFromGuard = nil
		}
	}

	ctx.Deny(ErrorAccessDeinied("None of the enforcers in any_of allowed the request"))
}

func (e EnforcerAnyOf) Enforcers() []Enforcer {
	enforcers := make([]Enforcer, len(e.EnforcerHolders))
	for i, enforcer := range e.EnforcerHolders {
		enforcers[i] = enforcer.Enforcer
	}
	return enforcers
}

func (e *EnforcerAnyOf) Append(enforcer Enforcer) {
	e.EnforcerHolders = append(e.EnforcerHolders, EnforcerHolder{enforcer})
}

type EnforcerDeny struct {
	TypeVal EnforcerType `json:"type" validate:"required"`
}

func (e *EnforcerDeny) Type() EnforcerType {
	return EnforcerTypeDeny
}

func (e *EnforcerDeny) Apply(ctx Context, next HandlerFunc) {
	ctx.Deny(ErrorAccessDeinied("Access denied by configuration"))
}

type EnforcerScope struct {
	TypeVal EnforcerType `json:"type" validate:"required"`
	Scope   string       `json:"scope" validate:"required"`
}

func (e *EnforcerScope) Type() EnforcerType {
	return EnforcerTypeScope
}

func (e *EnforcerScope) Apply(ctx Context, next HandlerFunc) {
	scopeStruct := struct {
		Scope string `json:"scope"`
	}{}
	if err := ctx.UnmarshalClaims(&scopeStruct); err != nil {
		ctx.Slogger().Error("Failed to get claims", "error", err)
		ctx.Deny(Error{
			HttpStatus:  403,
			Code:        "access_denied",
			Description: err.Error(),
		})
		return
	}

	scopes := strings.Split(scopeStruct.Scope, " ")
	for _, scope := range scopes {
		if scope == e.Scope {
			next(ctx)
			return
		}
	}

	ctx.Slogger().Warn("Scope not found in claims", "required", e.Scope, "actual", scopes)

	ctx.Deny(ErrorAccessDeinied("Scope not found in claims"))
}

type EnforcerSessionCookie struct {
	TypeVal        EnforcerType `json:"type" validate:"required"`
	CookieName     string       `json:"cookie_name" validate:"required"`
	DecryptKeyPath string       `json:"decrypt_key_path" validate:"required"`
	VerifyKeyPath  string       `json:"verify_key_path" validate:"required"`
}

func (e *EnforcerSessionCookie) Type() EnforcerType {
	return e.TypeVal
}

func (e *EnforcerSessionCookie) Apply(ctx Context, next HandlerFunc) {
	ctx.Slogger().Warn("EnforcerSessionCookie not implemented")
	ctx.Deny(ErrorAccessDeinied("EnforcerSessionCookie not implemented"))
}

type enforcerFunc struct {
	apply func(Context, HandlerFunc)
}

func (e *enforcerFunc) Type() EnforcerType {
	return EnforcerTypeCustom
}

func (e *enforcerFunc) Apply(ctx Context, next HandlerFunc) {
	e.apply(ctx, next)
}

func EnforcerFromFunc(apply func(Context, HandlerFunc)) Enforcer {
	return &enforcerFunc{apply}
}

type EnforcerAuthorizationBearer struct {
	TypeVal EnforcerType `json:"type" validate:"required"`
}

func (e *EnforcerAuthorizationBearer) Type() EnforcerType {
	return EnforcerTypeAuthorizationBearer
}

func (e *EnforcerAuthorizationBearer) Apply(ctx Context, next HandlerFunc) {
	internalCtx, ok := ctx.(*pepContext)
	if !ok {
		ctx.Slogger().Error("Failed to cast context to pepContext")
		ctx.Deny(Error{HttpStatus: 500, Code: "internal_error", Description: "Failed to cast context to pepContext"})
		return
	}

	if err := internalCtx.verifyAuthorizationBearer(); err != nil {
		ctx.Slogger().Warn("Failed to verify authorization bearer", "error", err)
		if pepErr, ok := err.(Error); ok {
			ctx.Deny(pepErr)
		} else {
			ctx.Deny(ErrorAccessDeinied("Failed to verify authorization bearer: " + err.Error()))
		}
		return
	}
	ctx.Slogger().Debug("Authorization bearer successfully verified")
	next(ctx)
}

type EnforcerAuthorizationDPoP struct {
	TypeVal       EnforcerType `json:"type" validate:"required"`
	NonceRequired bool         `json:"nonce_required" validate:"required"`
}

func (e *EnforcerAuthorizationDPoP) Type() EnforcerType {
	return EnforcerTypeAuthorizationDPoP
}

func (e *EnforcerAuthorizationDPoP) Apply(ctx Context, next HandlerFunc) {
	internalCtx, ok := ctx.(*pepContext)
	if !ok {
		ctx.Slogger().Error("Failed to cast context to pepContext")
		ctx.Deny(Error{
			HttpStatus:  500,
			Code:        "internal_error",
			Description: "Failed to cast context to pepContext",
		})
		return
	}

	options := dpop.ParseOptions{
		NonceRequired:         e.NonceRequired,
		AuthorizationRequired: true,
	}

	if err := internalCtx.verifyAuthorizationDPoP(options); err != nil {
		ctx.Slogger().Warn("Failed to verify authorization dpop", "error", err)
		if pepErr, ok := err.(Error); ok {
			ctx.Deny(pepErr)
		} else if dpopErr, ok := err.(*dpop.DPoPError); ok {
			ctx.Deny(Error{
				HttpStatus:  dpopErr.HttpStatus,
				Code:        dpopErr.Code,
				Description: dpopErr.Description,
			})

		} else {
			ctx.Deny(ErrorAccessDeinied("Failed to verify authorization dpop: " + err.Error()))
		}
		return
	}

	if e.NonceRequired {
		ctx.Deny(Error{
			HttpStatus:  500,
			Code:        "internal_error",
			Description: "Nonce required but not implemented",
		})
		return
	}

	ctx.Slogger().Debug("Authorization dpop successfully verified")
	next(ctx)
}
