// Package e2e holds developer-run, environment-guarded end-to-end tests for the zero-pdp
// authorization server.
//
// The suites are skipped unless ZERO_PDP_E2E_URL points at an already-running server
// (locally, or via a public tunnel such as rathole). Layers are selected by test-name prefix:
// Smoke, Regression, Flow, and HITL (the last is additionally gated by ZERO_PDP_E2E_HITL).
//
// Guiding rule: a non-HITL test asserts the furthest deterministic checkpoint reachable
// without a human (e.g. a successful pdp→IdP pushed authorization request, evidenced by the
// /authorization redirect carrying request_uri) and treats that as success. The full
// browser-login completion lives only in the opt-in HITL suite.
//
// See docs/e2e.md for the serve → tunnel → run workflow and environment variables.
package e2e
