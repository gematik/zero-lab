package proxy

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/go/pep"
)

// gatewayState is the per-request state shared across a context and any WithDeny clones the enforcer
// combinators make: the claims a gate sets, the resolved *Session, and the denial. Sharing it by pointer is
// what lets a gate's mutation survive AllOf/AnyOf (which clone the context via WithDeny).
type gatewayState struct {
	claimsRaw []byte
	session   *Session
	denied    bool
	denyErr   pep.Error
}

// gatewayContext implements pep.Context for the gateway's enforcer chain. It carries the resolved *Session
// (the stateful gate sets it) so the inject step can reach the per-session DPoP key. Deny records on the
// shared state; ServeHTTP maps it to a login redirect (401) or a status (403).
type gatewayContext struct {
	w     http.ResponseWriter
	r     *http.Request
	state *gatewayState
	deny  func(pep.Context, pep.Error)
}

func newGatewayContext(w http.ResponseWriter, r *http.Request) *gatewayContext {
	st := &gatewayState{}
	c := &gatewayContext{w: w, r: r, state: st}
	c.deny = func(_ pep.Context, err pep.Error) {
		st.denied = true
		st.denyErr = err
	}
	return c
}

func (c *gatewayContext) Writer() http.ResponseWriter { return c.w }
func (c *gatewayContext) Request() *http.Request      { return c.r }
func (c *gatewayContext) Deny(err pep.Error)          { c.deny(c, err) }
func (c *gatewayContext) Slogger() *slog.Logger       { return slog.Default() }
func (c *gatewayContext) SetClaims(raw []byte)        { c.state.claimsRaw = raw }

// WithDeny clones the context but shares the state, so claims/session a gate sets remain visible to the
// original context (and the terminal next).
func (c *gatewayContext) WithDeny(deny func(pep.Context, pep.Error)) pep.Context {
	cp := *c
	cp.deny = deny
	return &cp
}

func (c *gatewayContext) UnmarshalClaims(v any) error {
	if c.state.claimsRaw == nil {
		return errors.New("no claims")
	}
	return json.Unmarshal(c.state.claimsRaw, v)
}

// statefulGate is the gateway's opt-in kv session gate: it resolves the full session (identity + DPoP
// material) and stashes it on the shared state, so dpop routes can mint a proof. Denies 401 when there is no
// authenticated session.
type statefulGate struct {
	currentSession func(*http.Request) (*Session, bool)
}

func (g *statefulGate) Type() pep.EnforcerType { return pep.EnforcerTypeSessionCookie }

func (g *statefulGate) Apply(ctx pep.Context, next pep.HandlerFunc) {
	sess, ok := g.currentSession(ctx.Request())
	if !ok || !sess.Authenticated() {
		ctx.Deny(pep.ErrSessionRequired)
		return
	}
	if gc, ok := ctx.(*gatewayContext); ok {
		gc.state.session = sess
	}
	raw, err := json.Marshal(sess.Identity)
	if err != nil {
		ctx.Deny(pep.ErrSessionRequired)
		return
	}
	ctx.SetClaims(raw)
	next(ctx)
}
