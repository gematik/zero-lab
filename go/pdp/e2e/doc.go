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
