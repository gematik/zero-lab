package pep

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

type EnforcerType string

const (
	EnforcerTypeCustom        EnforcerType = "Custom"
	EnforcerTypeAllOf         EnforcerType = "AllOf"
	EnforcerTypeAnyOf         EnforcerType = "AnyOf"
	EnforcerTypeDeny          EnforcerType = "Deny"
	EnforcerTypeScope         EnforcerType = "Scope"
	EnforcerTypeSessionCookie EnforcerType = "SessionCookie"
)

type Enforcer interface {
	Type() EnforcerType
	Apply(ctx Context, next HandlerFunc)
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
	TypeVal   EnforcerType     `json:"type" validate:"required"`
	Enforcers []EnforcerHolder `json:"enforcers" validate:"required,dive"`
}

func (e EnforcerAllOf) Type() EnforcerType {
	return e.TypeVal
}

func (e EnforcerAllOf) Apply(ctx Context, next HandlerFunc) {
	if len(e.Enforcers) == 0 {
		slog.Warn("No enforcers confgured, denying request")
		ctx.Deny(ErrAccessDenied)
		return
	}
	var errorFromGuard *Error

	singleNext := func(ctx Context) {}

	singleDeny := func(ctx Context, err Error) {
		errorFromGuard = &err
	}

	subCtx := ctx.WithDeny(singleDeny)

	for _, enforcer := range e.Enforcers {
		slog.Info("Applying enforcer", "type", enforcer.Type())
		enforcer.Apply(subCtx, singleNext)
		if errorFromGuard != nil {
			ctx.Deny(*errorFromGuard)
			return
		}
	}

	next(ctx)
}

type EnforcerAnyOf struct {
	TypeVal   EnforcerType     `json:"type" validate:"required"`
	Enforcers []EnforcerHolder `json:"enforcers" validate:"required,dive"`
}

func (e EnforcerAnyOf) Type() EnforcerType {
	return e.TypeVal
}

func (e EnforcerAnyOf) Apply(ctx Context, next HandlerFunc) {
	if len(e.Enforcers) == 0 {
		slog.Warn("No enforcers confgured, denying request")
		ctx.Deny(ErrAccessDenied)
		return
	}
	var errorFromGuard *Error

	singleNext := func(ctx Context) {}

	singleDeny := func(ctx Context, err Error) {
		errorFromGuard = &err
	}

	subCtx := ctx.WithDeny(singleDeny)

	for _, enforcer := range e.Enforcers {
		slog.Info("Applying enforcer", "type", enforcer.Type())
		enforcer.Apply(subCtx, singleNext)
		if errorFromGuard == nil {
			next(ctx)
			return
		} else {
			errorFromGuard = nil
		}
	}

	ctx.Deny(ErrAccessDenied)
}

type EnforcerDeny struct {
	TypeVal EnforcerType `json:"type" validate:"required"`
}

func (e *EnforcerDeny) Type() EnforcerType {
	return e.TypeVal
}

func (e *EnforcerDeny) Apply(ctx Context, next HandlerFunc) {
	ctx.Deny(ErrAccessDenied)
}

type EnforcerScope struct {
	TypeVal EnforcerType `json:"type" validate:"required"`
	Scope   string       `json:"scope" validate:"required"`
}

func (e *EnforcerScope) Type() EnforcerType {
	return e.TypeVal
}

func (e *EnforcerScope) Apply(ctx Context, next HandlerFunc) {
	scopeStruct := struct {
		Scope string `json:"scope"`
	}{}
	if err := ctx.Claims(&scopeStruct); err != nil {
		ctx.Slogger().Error("Failed to get claims", "error", err)
		ctx.Deny(ErrAccessDenied)
		return
	}

	scopes := strings.Split(scopeStruct.Scope, " ")
	for _, scope := range scopes {
		if scope == e.Scope {
			next(ctx)
			return
		}
	}

	ctx.Slogger().Warn("Scope not found", "required", e.Scope, "actual", scopes)

	ctx.Deny(ErrAccessDenied)
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
	ctx.Deny(ErrAccessDenied)
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
