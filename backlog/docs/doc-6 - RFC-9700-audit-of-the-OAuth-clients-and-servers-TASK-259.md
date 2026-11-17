---
id: doc-6
title: RFC 9700 audit of the OAuth clients and servers (TASK-259)
type: other
created_date: '2026-11-17T06:45:00Z'
---


Audit date: 2026-11-17, main at b4999ee6. Read-only. Source: RFC 9700 (January 2025), §2.1–2.7 and §4.1–4.19.
In practice §2 runs to 2.6 and §4 to 4.17: 2.7 and 4.18/4.19 do not exist in the published RFC.
go/pdp is out of scope: zeta-pdp-go replaces it and is checked there.

Most authorization-server rules (2.1 exact redirect matching, 2.1.1 PKCE enforcement and downgrade (4.8), 4.11.2, 4.12 (307),
4.14 refresh-token rotation, 4.15, 4.16 clickjacking, 4.17 postMessage origins) have no subject left in scope.
Every in-scope component is a client, a resource server, a library for one, or an Authenticator (user-agent role).
The AS rows below are recorded once per component as n/a with that reason.

Statuses: **met**, **gap** (new task proposed below, or an existing task named), **n/a** (with the reason).

---

## 1. zero-pep-proxy (go/pep/proxy): confidential client, token-mediating backend

It has two backends. The provider backend is the RP of several OIDC/OIDF/idpd IdPs and keeps the session itself
(`backend_provider.go`). The PDP backend is a confidential client of one AS with PAR, PKCE, DPoP and private_key_jwt
(`backend_pdp.go`).

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1, 4.1.3 | AS compares redirect URIs exactly | n/a | AS rule. pep sends one fixed configured redirect_uri (`openid/request.go:57`, `backend_pdp.go:413`, `cmd/zero-pep-proxy/config.go:53`) |
| 2.1, 4.11.1 | Client exposes no open redirector (`rd=`) | met | `sanitizeReturnTo` `proxy.go:584-596`, used in `proxy.go:312,327` and `gateway.go:216`. Test `TestRFC9700_4_11_1_SanitizeReturnTo`. Encoding of `rd` in the shipped Caddyfile: TASK-351 |
| 2.1, 4.11.1 | Client does not send the browser to an unchecked URL | gap → TASK-352 | Decoupled flow: the AS's `Location` becomes the page's login URL unchecked (`backend_pdp.go:497-516`, rendered in `qr.html:37`, `authenticator.html`) |
| 2.1, 4.7 | CSRF at the redirection endpoint (attacker's code into the victim's session) | met | `state` resolves a server-side session (`proxy.go:443`, `session.go:237-243`). A browser without that session's cookie never receives it (`proxy.go:477-481,498-501`). PKCE S256 (`backend_provider.go:102-103`, `backend_pdp.go:403-404,417-418`) and nonce (provider backend) as well |
| 2.1, 4.4 | Mix-up defence when the client talks to more than one AS (RFC 9207 `iss`, or a distinct redirect URI per issuer) | **gap (new, G4)** | Provider backend: several static IdPs plus every OIDF federation IdP share one `/oauth2/callback`. The callback reads neither `iss` (`proxy.go:440-462`) nor which path it arrived on. The ID token `iss` check (`openid/claims.go:81`) runs only after the code went to the stored issuer's token endpoint. PDP backend: n/a, one AS (`backend_pdp.go:72,134`) |
| 2.1 | AS does not forward user credentials on redirect | n/a | AS rule |
| 2.1.1, 4.5.3.1 | PKCE for the authorization code | met | Both backends always send S256 (`openid/request.go:62-63`, `backend_pdp.go:417-418`). Tests `TestRFC7636_4_3_AuthorizationQuerySendsPKCEAndNeverTheVerifier`, `TestPDPStartLoginPreparesSession` |
| 2.1.1 | Challenge/nonce transaction-specific and bound to the user agent that started the transaction | **gap (new, G1)** | A fresh verifier, nonce and state per login (`backend_provider.go:100-103`, `backend_pdp.go:401-404`), but the callback completes the login before checking the cookie (`proxy.go:457` precedes `proxy.go:477`). In redirect mode a callback from another browser therefore authenticates the session of whoever started the login. Attacker: start a login, send the IdP URL to the victim, and the victim's (SSO) login lands in the attacker's session |
| 2.1.1 | S256, the verifier never exposed | met | `openid/request.go:62-63`, `pkce.go:36-49`. Test `TestRFC7636_4_1_VerifierIsFreshAndCarries32Octets` |
| 2.1.1, 4.8 | AS supports and enforces PKCE, downgrade protection | n/a | AS rules |
| 2.1.2, 4.6 | No implicit grant or token-in-front-channel response types | met | `response_type=code` only (`openid/request.go:58`, `backend_pdp.go:411`). No `token` response type anywhere in scope |
| 2.2.1, 4.10.1 | Sender-constrained access tokens | met | PDP backend: a per-session DPoP key (`backend_pdp.go:396-400`) and a DPoP proof on every token request (`backend_pdp.go:575-629`, test `TestPDPTokenRequestSendsDPoP`). Forwarded with a fresh proof (`gateway.go:256`, test `TestGatewayDPoPInjection`). `token_type` not checked: TASK-352. Provider backend forwards no tokens (n/a) |
| 2.2.2, 4.14 | Refresh tokens sender-constrained or rotated (public clients) | met | Confidential client. The refresh grant carries private_key_jwt plus a DPoP proof (`backend_pdp.go:546-554`). Refresh tokens stay server-side in a sealed store (`session.go:105-108`) |
| 2.3 | Least privilege: the client asks for the scope it needs | gap → TASK-351 | `scope` and `idp_iss` from the browser's query go to the AS unchecked (`proxy.go:345`, `backend_pdp.go:405-407,420-422`) |
| 2.4 | No resource owner password grant | met | Not implemented (no `grant_type=password` in go/ or rust/) |
| 2.5 | Asymmetric client authentication | met | PDP backend: private_key_jwt ES256 (`backend_pdp.go:153-200`, test `TestPDPClientAssertionClaims`). Claim shape per RFC 7523bis: TASK-269. Provider backend OIDC IdPs: see go/openid |
| 2.6 | Client configures itself from AS metadata | met | RFC 8414 discovery with issuer equality and https endpoints (`backend_pdp.go:305-355`). Tests `TestRFC8414_3_3_MetadataNamingAnotherIssuerIsRefused`, `TestRFC6749_10_9_AuthorizationAndTokenEndpointsMustBeHTTPS`, `TestServerRule2_MetadataDiscoveryDoesNotFollowARedirect` |
| 2.6 | TLS end to end, no authorization response over http | met | Endpoints https-only except an issuer on localhost (`backend_pdp.go:284-303`). Session cookie `__Host-`/Secure, and the insecure variant refused off localhost (`cookie.go:31-45`, `cmd/zero-pep-proxy/main.go:105-111`) |
| 2.6, 4.17 | In-browser (postMessage) response strictly verified | n/a | No postMessage: redirects and `/oauth2/poll` only |
| 2.6 | No CORS at the authorization endpoint | n/a | AS rule |
| 4.2.4 | Callback page carries no third-party resources or links | met | `complete.html` and `error.html` link only to same-origin `/oauth2/*`. Styles inline (`webui/templates`) |
| 4.2.4 | Referrer-Policy on the page rendered for the authorization response | **gap (new, G7, low)** | No `Referrer-Policy` and no `Cache-Control: no-store` on any `/oauth2/callback` response (`proxy.go:440-494`, `render.go:55-56`). The error page keeps `code` and `state` in its URL |
| 4.2.4 | `state` invalidated after its first use at the redirection endpoint | gap (G7, low) | Consumed only after a successful exchange (`proxy.go:461-463`, test `TestRFC9700_2_1_SessionStateSingleUse`). A failed exchange leaves it valid for `LoginStateTTL` (`proxy.go:457-459`, `session.go:45`) |
| 4.3.1 | Code in browser history harmless | met | One-time code, PKCE and client authentication (PDP backend). The callback answers with 302 (`proxy.go:493`) |
| 4.3.2 | Access tokens never in URLs | met | Tokens never leave the server. The cookie is an opaque random value (`session.go:144-193`). `/oauth2/userinfo` returns identity only (`proxy.go:414-422`) |
| 4.5.3.2 | Nonce checked on the token-endpoint ID token before any token is used | met | The provider backend passes the session's nonce (`backend_provider.go:127`, test `TestCompleteHandsTheSessionsNonceToTheExchange`). See go/openid |
| 4.7.1 | Make sure the AS supports PKCE before relying on it for CSRF | met | Not relied on alone: `state` is used too (`proxy.go:443`) |
| 4.9.3 | Tokens not stored or logged in plaintext | met | Sealed session store (`session.go:105-108`). Logs carry no query or secrets (`proxy.go:299-308`, tests `TestServerRule14_ALoginLogsNoSessionIDNorCookieNorStateAtDebug`, `TestServerRule14_SessionLookupErrorsNameNeitherIDNorState`) |
| 4.9, 4.13 | Reverse proxy sanitises the security-relevant headers it forwards | met (headers) / **gap (new, G8, low)** (cookies) | Client `Authorization` and identity headers dropped (`gateway.go:186-191`), identity headers cleared before setting (`headers.go:39-43`). forward_auth relies on Caddy `copy_headers` (`cmd/zero-pep-proxy/Caddyfile:28`). But the gateway forwards pep's own `__Host-ZERO-PEP-SID` and `-SNAP` cookies upstream (`gateway.go:171-205`), and those are the bearer credential of a BFF session that holds DPoP-bound tokens |
| 2.1 (CSRF), RFC 6819 §4.4.1.8 class | State-changing endpoints resist cross-site requests (sign-out) | **gap (known, new task G5)** | `GET /oauth2/sign_out` ends the session with no CSRF check (`proxy.go:197,508-530`). Only POST needs `X-Requested-With` (test `TestServerRule2_SignOutByPOSTRequiresCSRFProtection`). Related: a cross-site top-level `GET /oauth2/start` replaces the cookie of a signed-in browser (`proxy.go:343-354`) |
| 4.12, 4.14, 4.15, 4.16 | 307, refresh rotation, client_id confusion, clickjacking | n/a | AS rules |

## 2. go/pep: resource-server library (token verification, DPoP)

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.2.1, 4.10.1 | RS checks sender-constrained tokens | met | `verifyAuthorizationDPoP` `pep.go:379-422`: cnf.jkt, proof, ath, htm/htu, nonce. Tests `TestDPoPEnforcer`, `TestRFC9449_7_1_AnInvalidDPoPTokenIsRefusedWith401InvalidToken`, `TestRFC9449_9_*` |
| 4.10.1 | A sender-constrained token is not accepted without its proof | **gap (new, G2)** | `EnforcerAuthorizationBearer` (`enforcers.go:297-316`) → `verifyAuthorizationBearer` (`pep.go:359-374`) accepts a token with `cnf.jkt` under the Bearer scheme with no proof. A stolen DPoP-bound token works on every bearer route of the same PEP (RFC 9449 §7.2) |
| 4.10.1, RFC 9449 §11.1 | DPoP proof replay detected across replicas | met (lib) | The PEP refuses to build without Replays (`pep.go:109-113`). Tests `TestRFC9449_11_1_ProofReplayedAtAnotherReplicaIsRefusedWithSharedReplays`, `TestServerRule17_BuildRefusesABuilderWithoutReplays`. Host wiring for zaddy: TASK-310 |
| 4.13 | htu from the configured origin, never from Host or X-Forwarded-* | met | `pep.go:398-403` (`publicOrigin`). Path after a Caddy rewrite: TASK-359 |
| 2.3, 4.10.2 | RS refuses tokens not meant for it (audience) | **gap (new, G3)** | Audience is checked only when `Resource` is set (`token.go:228`, `pep.go:225-233`). `Build` accepts no resource (`pep.go:80-127`). Test `TestVerifyAccessToken_AudienceOptional` asserts this for "authorization-server use", which left with go/pdp. No `typ` `at+jwt` check (RFC 9068 §4), so a JWT of another kind signed by a key in the set (an ID token) passes when no audience is set |
| 2.3 | Restrict tokens to actions (scope) | met | `EnforcerScope` `enforcers.go:230-262`. Test `TestEnforcerScope` |
| 4.3.2 | Tokens only from the Authorization header, never the query | met | `parseAuthorizationScheme` `pep.go:452-470`, `dpop.AccessToken`. Bounds: TASK-353 |
| 4.9.3 | RS does not store or log tokens in plaintext | met | Nothing stored. Tests `TestServerRule14_ARefusedTokensHeaderIsNotQuoted`, `TestServerRule14_RefusedTokenClaimsAreNotQuoted`, `TestServerRule14_ADeniedRequestIsLoggedWithoutItsQuery` |
| 4.15 | Distinguish client and user tokens | n/a | AS rule (identifier namespaces are the AS's) |
| 2.6 | End-to-end TLS | n/a | Library. TLS is the host's (principle 2) |

## 3. zaddy (go/zaddy): Caddy resource server over go/pep

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.2.1, 4.10.1 | DPoP routes | met | `authorization_dpop [nonce_required]` `enforce_policy.go:109-121`, nonce keys `zaddy.go:107-125` |
| 4.10.1 | Bearer routes do not take DPoP-bound tokens | **gap (G2)** | `authorization_bearer` `enforce_policy.go:104-108` runs the bearer enforcer of go/pep. The shipped `Caddyfile` has both schemes on one PEP |
| 4.10.1, RFC 9449 §11.1 | Replay detection across replicas | gap → TASK-310 | `dpop.NewMemoryReplays` `zaddy.go:82-90` |
| 2.3, 4.10.2 | Audience restriction always on | **gap (G3)** | `resource` optional (`zaddy.go:51,86`). An unset resource checks no audience |
| 2.3 | Scope per route | met | `scope` directive `enforce_policy.go:122-130` |
| 4.13 | Path judged as received | gap → TASK-359 | `enforce_policy.go:76-84`, `pep.go:401` |
| 4.9.3 | No tokens in logs | met | The per-request log names the policy only (`enforce_policy.go:77`). go/pep's logging as above |

## 4. go/openid: OIDC relying-party library (used by pep's provider backend, idpd, oidf)

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1.1 | PKCE S256 on every authorization request | met | `request.go:62-63`. Tests `TestRFC7636_4_3_AuthenticationURLCarriesTheS256Challenge`, `TestRFC7636_4_3_AuthorizationQuerySendsPKCEAndNeverTheVerifier`, `TestRFC7636_AppendixB_S256ChallengeMatchesTheExample` |
| 2.1.1 | Verifier transaction-specific | met | 32 random octets per login (`pkce.go:42-49`). Test `TestRFC7636_4_1_VerifierIsFreshAndCarries32Octets` |
| 2.1, 4.5.3.2 | Nonce required and checked on the token-endpoint ID token before tokens are returned | met | `claims.go:87-92` (constant time, empty expectation refuses), `client.go:144-151`. Tests `TestOIDCCore_3_1_3_7_IDTokenChecksBindTheTokenToTheLogin`, `TestOIDCCore_3_1_3_7_ExchangeRefusesAnIDTokenThatFailsValidation`, `TestIDTokenChecksWithAnEmptyExpectationRefuseEverything` |
| 2.1.2 | `response_type=code` | met | `request.go:58` |
| 2.1, 4.4.2.1 | Mix-up: the authorization response's `iss` compared with the stored issuer | **gap (G4)** | The library has no authorization-response check. ID token `iss` = discovery issuer (`claims.go:81`, `client.go:167`) is a token-endpoint check, after the code went out |
| 2.5 | Asymmetric client authentication available | **gap (new, G9, low)** | Only `client_secret_post` (`client.go:122-124`). `Config.Validate` requires a secret (`client.go:186-197`) |
| 2.6 | Metadata used, issuer equal, https | met | `discovery.go:53-86`. Tests `TestOIDCDiscovery_4_3_ADocumentNamingAnotherIssuerIsRefused`, `TestOIDCDiscovery_3_RefusesAnythingButHTTPS` |
| 2.4 | No ROPC | met | Not implemented |
| 4.3.2 | Tokens never in URLs | met | Token response returned to the host only (`client.go:118-152`) |
| 4.1.3, 4.8, 4.11.2, 4.12, 4.14–4.17 | AS rules | n/a | Client library |

## 5. go/oidf: TI federation relying party

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1.1 | PKCE | met | `openid.AuthorizationQuery` via PAR (`client.go:87-136`), `checkVerifier` (`client.go:173-175`). Test `TestRFC7636_4_6_AVerifierOtherThanTheChallengesIsRefused` |
| 2.1, 4.5.3.2 | Nonce, ID token bound to the login | met | `client.go:228-231`. Test `TestA_23049_AnIDTokenOfAnotherLoginIsRefused` |
| 2.1, 4.1.3 | Redirect URI byte for byte one the served statement registers | met | `values.go:326-330`, `client.go:105,178`. Tests `TestRFC9700_4_1_3_TheRedirectURIIsComparedExactly`, `TestRFC9700_4_1_3_TheRedirectURIsAreThoseOfTheServedStatement`, `TestA_27585_TheRedirectURIsAreHTTPSWithoutQueryFragmentOrUserInfo` |
| 2.1, 4.4 | Mix-up defence among federation IdPs | **gap (G4)** | One redirect URI for every admitted IdP. No RFC 9207 `iss` check at the callback. Admission by the master's IdP list narrows the attacker to federation members (`client.go:62-71`, test `TestFedMaster_IdPList_AnUnlistedIDPIsRefusedBeforeAnyFetch`) |
| 2.1.2 | Code flow only | met | `response_type=code` through `openid.AuthorizationQuery` |
| 2.3 | Scope limited to the registered scope | met | `checkLogin` (`client.go:101`). Tests `TestA_23034_02_AScopeThatIsNotRegisteredIsNotAskedFor`, `TestServerRule17_AConfiguredScopeThatIsNotRegisteredIsRefused` |
| 2.5 | Asymmetric client authentication | met | `self_signed_tls_client_auth` (`relying_party.go:635`). Test `TestRFC8705_2_2_AClientCertificateOtherThanTheStatementsIsRefusedAtPAR` |
| 2.6 | Metadata from verified statements | met | Tests `TestOIDF_10_2_*`, `TestOIDF_5_2_1_ASignedJwksNotSignedByTheStatementsKeyIsRefused`, `TestServerRule2_FederationDoesNotFollowARedirect` |
| 4.3.2, 4.9.3 | Tokens not in URLs or logs | met | ID token decrypted in memory (`client.go:247-267`). Test `TestServerRule14_AnIdentityDoesNotLogItsPersonalClaims` |
| AS rules (4.8, 4.11.2, 4.12, 4.14–4.17) | | n/a | RP only (`oidftest` is a test IdP, not shipped) |

## 6. go/idpd: client of the gematik IDP-Dienst, plus Authenticator

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1.1 | PKCE (public client: MUST) | met | `openid.AuthorizationQuery` (`client.go:191-201`). The verifier travels in the encrypted `key_verifier` (`client.go:230-246`) |
| 2.1, 4.5.3.2 | Nonce and ID token checked before tokens are used | met | `client.go:271-283,313-325`. Tests `TestOIDCCore_3_1_3_7_ExchangeRefusesAnIDTokenOfAnotherLogin`, `TestOIDCCore_3_1_3_3_ExchangeRefusesAResponseWithoutAnIDToken`, `TestCheckIDTokenRefusesAnyAlgorithmButBP256R1` |
| 2.6 | Signed metadata, trusted issuer | met | Tests `TestASignedDiscoveryDocumentOfAnotherIssuerIsRefused`, `TestIDPV001TheDiscoverySignerIsCheckedBeforeItsKeyIsUsed`, `TestIDPV003ThereIsNoClientWithoutTrust` |
| 2.5 | Client authentication | n/a | The IDP-Dienst registers public clients (PKCE and `key_verifier`) |
| 2.2.2 | Refresh tokens | n/a | None used |
| 4.4 | Mix-up | n/a | One IDP per client. The multi-IdP host is pep (G4) |
| 4.3.2 | Tokens never in URLs | met | Tokens decrypted from the token response (`client.go:276-288`) |
| (Authenticator) | User-agent role: fetches the challenge from the URL it is handed | n/a for RFC 9700. See related finding G10 | `authenticator.go:179` GETs any `authURL`. The Rust counterpart pins the IDP origin |

## 7. go/epa: authorization at the Aktensystem

zero-epa is the Authenticator in this flow. The Aktensystem is the OAuth client of the IDP-Dienst, keeps PKCE and state,
and is the resource server.

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1, 2.1.1, 4.4, 4.7 | Client rules (PKCE, state, mix-up, CSRF) | n/a | The Aktensystem builds the request (`authz.go: SendAuthorizationRequestSC`) and redeems the code |
| 4.2, 4.3.1 | Code does not leak through Referer or history | met | The code goes from the IDP's `Location` straight into the VAU channel (`authz.go: Authorize` → `SendAuthCodeSC`), never through a browser |
| 4.11.1 | No open redirector | n/a | No browser redirects. Outbound redirects: TASK-357 |
| 2.3, 4.9 | Callers of the proxy restricted | n/a (not OAuth) → TASK-362 | The zero-epa proxy authenticates no caller |
| 2.4 | No ROPC | met | Not used |

## 8. go/dpop and go/nonce: DPoP libraries

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.2.1, 4.10.1 | Proof verification complete (typ, alg, signature, jwk, htm, htu, iat, nonce, ath, jkt) | met | `dpop/verify.go`. Tests `TestRFC9449_4_3_00` … `TestRFC9449_4_3_12_*`, `TestRFC9449_10_GrantBoundToAnotherKeyIsRefused`. Traceability `dpop/TRACEABILITY.md` |
| 4.10.1 | Replay refused, fail closed | met | Tests `TestRFC9449_11_1_ReplayedProofIsRefused`, `TestRFC9449_11_1_FullReplaysFailClosed`, `TestServerRule16_AReplaysErrorRefusesTheProof` |
| 4.10.1 | Server nonces single-use or windowed, unforgeable | met | Tests `TestServerRule11_ANonceIsRedeemedOnce`, `TestServerRule11_ConcurrentRedeemsHaveExactlyOneWinner`, `TestRFC9449_8_ASourceNonceMustMatchExactly`, `TestServerRule10_AForgedOrAlteredNonceIsRefusedWithoutAStoreCall` |
| 2.2.2 | Proofs for refresh (sender-constrained RT, client side) | met | Test `TestRFC9449_Figure7_RefreshProofVerifies`. Client proofs `TestRFC9449_4_2_*` |
| other | | n/a | Libraries without a flow of their own |

## 9. rust/ti-idpd-client: Authenticator-Modul of the IDP-Dienst

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1, 2.1.1, 4.4, 4.5, 4.7 | Client rules | n/a | "What this crate does not do: the relying-party side" (`src/lib.rs` crate doc). PKCE and state belong to the RP |
| 4.2, 4.3 | Code leakage | n/a | Returns the IDP's 302 `Location` to the host without following it (`src/authenticator.rs:156`). Test `a_20526_the_flow_yields_the_code_and_posts_a_well_formed_signed_challenge` |
| 2.4 | No ROPC | met | Challenge-response with a card only |
| AS rules | | n/a | |

## 10. rust/ti-directory-client: client of the FHIR directory and its Keycloak

| RFC 9700 | Requirement | Status | Evidence |
|---|---|---|---|
| 2.1, 4.1, 4.11 | The owner flow's code goes only to the directory, and the authorization URL only to its own IDP | met | `owner.rs` `sign_in`, `to_own_idp`. Tests `the_sign_in_follows_the_idps_redirect_only_to_the_directory`, `a_redirect_to_another_idp_is_refused_before_anything_is_signed` |
| 2.1.1, 4.7 | PKCE and state | n/a | The directory is the RP and keeps the OpenID state (`src/lib.rs` crate doc) |
| 2.2.1 | Sender-constrained access tokens | n/a | gemSpec_VZD_FHIR_Directory issues bearer tokens. The AS and RS decide |
| 2.4 | No ROPC | met | `client_credentials` only (`keycloak.rs` `token_request`). Test `rfc_6749_4_4_2_the_keycloak_request_is_client_credentials_with_basic_auth` |
| 2.5 | Asymmetric client authentication | n/a | The Keycloak realm prescribes `client_secret_basic`. The client follows the AS |
| 4.3.2 | Tokens only in the Authorization header | met | `tokens.rs` `send_once`, `request.rs` `get_bearer`. Tests `rfc_6750_3_1_a_refused_token_is_reported_and_the_request_retried_once`, `a_token_the_directory_accepts_is_sent_once_and_kept` |
| 2.6 | TLS | n/a | Sans-I/O core. The host transport (ti-client, https-only builders `ti-client/src/http.rs:138-182`) owns TLS |

---

## Counts

| Component | met | gap | n/a |
|---|---|---|---|
| zero-pep-proxy | 18 | 8 (new: G1, G4, G7 ×2, G8; known: G5; existing: TASK-351, TASK-352) | 6 |
| go/pep | 6 | 2 (G2, G3) | 2 |
| zaddy | 3 | 4 (G2, G3, TASK-310, TASK-359) | 0 |
| go/openid | 7 | 2 (G4, G9) | 1 |
| go/oidf | 8 | 1 (G4) | 1 |
| go/idpd | 4 | 0 (+ related G10) | 4 |
| go/epa | 2 | 0 | 3 |
| go/dpop, go/nonce | 4 | 0 | 1 |
| rust/ti-idpd-client | 1 | 0 | 3 |
| rust/ti-directory-client | 3 | 0 | 4 |

The pep-proxy row "4.9, 4.13" counts once as met (headers) and once as gap (cookies). Rows that only point to an existing task
count as gaps.

---

## Gaps: proposed tasks, by severity

### G1 → TASK-364 [HIGH] pep/proxy: a login completes only in the browser that started it
**Description.** `handleCallback` (`go/pep/proxy/proxy.go:440-494`) resolves the session by `state` and calls
`backend.Complete` (`proxy.go:457`) before it checks that the request carries the session's cookie
(`requestOwnsSession`, `proxy.go:477`). That check only chooses between redirecting and rendering `complete.html`. In
redirect mode (plain OIDC, and the PDP backend for non-OIDF providers, `backend_provider.go:111-117`,
`backend_pdp.go:441-447`), an attacker can start a login, keep the cookie, and lure a victim to the IdP authorization
URL. With an IdP SSO session no interaction is needed. The victim's callback then authenticates the attacker's session
with the victim's identity. RFC 9700 §2.1.1 requires the PKCE challenge or nonce to be bound to the user agent that
started the transaction. Here it is bound only to a server-side session that any browser can complete. Decoupled (OIDF
QR) and authenticator (idpd) modes are cross-device by design. They need the cross-device mitigations instead (short
lifetime, the user sees what they confirm, draft-ietf-oauth-cross-device-security), not the cookie check.

**Acceptance criteria.**
- In redirect mode a callback without the cookie of the session its `state` names is refused before the code is redeemed, and the state is consumed. Test named after RFC 9700 §2.1.1.
- The login mode is recorded on the session at `/oauth2/start`, so the callback knows which rule applies. Decoupled and authenticator modes keep working (e2e).
- The remaining cross-device risk of decoupled and authenticator logins is written down in the pep/proxy docs, with the mitigations in force.

### G2 → TASK-365 [HIGH] pep: a DPoP-bound access token is refused under the Bearer scheme
**Description.** `EnforcerAuthorizationBearer` (`go/pep/enforcers.go:297-316`) → `verifyAuthorizationBearer`
(`go/pep/pep.go:359-374`) accepts any verified JWT, including one whose `cnf.jkt` binds it to a DPoP key
(`token.go:62-75`). A leaked DPoP-bound token can therefore be replayed without a proof at any `authorization_bearer`
route of the same PEP (zaddy `enforce_policy.go:104-108`; the shipped `zaddy/Caddyfile` has both schemes). That voids
sender-constraining (RFC 9700 §2.2.1, §4.10.1; RFC 9449 §7.2).

**Acceptance criteria.**
- The bearer enforcer refuses a token with a `cnf` member (`invalid_token`, 401). A test named after RFC 9449 §7.2 / RFC 9700 §4.10.1 proves it.
- An `any_of` of bearer and DPoP still admits the DPoP-bound token with a valid proof.

### G3 → TASK-366 [MEDIUM] pep and zaddy: every access token is audience-restricted and typed
**Description.** `validateClaims` checks `aud` only when a resource is configured (`go/pep/token.go:228`).
`Builder.Build` (`go/pep/pep.go:80-127`) accepts a PEP without `Resource`, and zaddy's `resource` is optional
(`go/zaddy/zaddy.go:51,86`). `TestVerifyAccessToken_AudienceOptional` (`go/pep/verify_test.go:35`) keeps that mode for
"authorization-server use", which left with go/pdp. Nor is the JWT `typ` checked (RFC 9068 §4 `at+jwt`), so another
JWT signed by a key in the set (an ID token) is taken for an access token. RFC 9700 §2.3 and §4.10.2: the RS MUST refuse
a token not meant for it.

**Acceptance criteria.**
- `Build` refuses a PEP without a resource, and zaddy refuses a config without `resource`. Tests named after RFC 9700 §4.10.2.
- A token whose `typ` is not `at+jwt` (or `application/at+jwt`) is refused, unless the operator opts in for an AS known to omit it. Test named after RFC 9068 §4.
- `TestVerifyAccessToken_AudienceOptional` is replaced by a test that the audience is required.

### G4 → TASK-367 [MEDIUM] Mix-up defence for pep's provider backend (openid, oidf, pep/proxy)
**Description.** The provider backend talks to several authorization servers: static OIDC IdPs, the idpd client and
every OIDF federation IdP (`go/pep/proxy/backend_provider.go:63-68`). All of them come back through one
`/oauth2/callback` (`cmd/zero-pep-proxy/config.go:53`). The callback (`proxy.go:440-462`) reads neither the RFC 9207
`iss` parameter nor which path the response arrived on. go/openid has no check of an authorization response's `iss`.
The ID token `iss` check (`go/openid/claims.go:81`, `go/oidf/client.go:228`) runs after the code was already sent to
the stored issuer's token endpoint, too late against mix-up (RFC 9700 §4.4.2.1). RFC 9700 §2.1 REQUIRES a mix-up
defence for a client of more than one AS. Federation admission (`go/oidf/client.go:62-71`) limits the attacker to
federation members.

**Acceptance criteria.**
- go/openid offers the RFC 9207 check: `iss` present when the AS metadata announces `authorization_response_iss_parameter_supported`, and equal to the stored issuer. Tests named after RFC 9207 §2.4.
- pep's callback compares the response's `iss` with the session's `IDPIss` before `Complete`, and refuses a mismatch. Where an IdP sends no `iss`, distinct per-issuer redirect URIs (RFC 9700 §4.4.2.2) are used instead, or the gap is recorded for that IdP.
- Which TI IdPs (IDP-Dienst, federation IdPs) send `iss` is checked against gemSpec and noted in the task.

### G5 → TASK-368 [MEDIUM] pep/proxy: sign-out and login start resist cross-site requests (known)
**Description.** `GET /oauth2/sign_out` (`go/pep/proxy/proxy.go:197,508-530`) ends the session without a CSRF check,
so any site can sign a user out with a link or an image (logout CSRF; RFC 9700 §2.1 CSRF, RFC 6819 §4.4.1.8 class).
Only POST requires `X-Requested-With` (test `TestServerRule2_SignOutByPOSTRequiresCSRFProtection`). Likewise a
cross-site top-level `GET /oauth2/start` creates a pending session and overwrites the cookie of a signed-in browser
(`proxy.go:343-354`). Found by the rule 28 audit and recorded in TASK-259's notes.

**Acceptance criteria.**
- GET `/oauth2/sign_out` only renders a confirmation page whose form POSTs with a per-session token (or `Sec-Fetch-Site: same-origin`). A cross-site request leaves the session intact. Test named after the requirement.
- `/oauth2/start` does not replace an authenticated session's cookie on a cross-site request, or the decision to allow it is recorded with its reason.

### G6 [MEDIUM] existing tasks that hold RFC 9700 gaps (no new task)
- TASK-351: `scope`/`idp_iss` from the browser go to the AS unchecked (§2.3); `rd` encoding in the Caddyfile (§4.11.1).
- TASK-352: the PDP backend takes `token_type` unchecked (§2.2.1). The AS's `Location` becomes the page's login URL unchecked (§4.11.1).
- TASK-310: zaddy DPoP replay detection per replica only (§4.10.1); fixed on fix/elder-tasks.
- TASK-359: zaddy htu and path after Caddy's normalisation (§4.13).
- TASK-269 (closed, not applicable: one configured AS, gemSpec_ZETA profile): client assertion `aud` and `typ` per RFC 7523bis (§2.5).
- TASK-353: Bearer credentials and cookies bounded before verification.

### G7 → TASK-369 [LOW] pep/proxy: the authorization response page leaks nothing and its state is used once
**Description.** No response of `/oauth2/callback` (`go/pep/proxy/proxy.go:440-494`; renderer `render.go:55-56`)
sets `Referrer-Policy: no-referrer` or `Cache-Control: no-store`. The error page is rendered at the URL that carries
`code` and `state` (RFC 9700 §4.2.4, §4.3.1). The state is consumed only after a successful exchange
(`proxy.go:461-463`). After a failed exchange it stays valid for `LoginStateTTL` (15 min, `session.go:45`), whereas
§4.2.4 says it SHOULD be invalidated on first use.

**Acceptance criteria.**
- Every callback response carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. Test named after RFC 9700 §4.2.4.
- The state is consumed on the first callback that names it, whatever its outcome. Test extends `TestRFC9700_2_1_SessionStateSingleUse`.

### G8 → TASK-370 [LOW] pep/proxy gateway: pep's own cookies are not forwarded upstream
**Description.** The gateway's `Rewrite` (`go/pep/proxy/gateway.go:171-205`) strips `Authorization` and the identity
headers. It still forwards the `Cookie` header, including `__Host-ZERO-PEP-SID` and `-SNAP`. Those cookies are the
credential of a BFF session that holds DPoP-bound tokens and their key, so a compromised upstream can ride the session
(RFC 9700 §4.9, §4.13).

**Acceptance criteria.**
- The gateway removes its own session and snapshot cookies from upstream requests and keeps the others. Test named after the requirement.

### G9 → TASK-371 [LOW] openid: private_key_jwt client authentication
**Description.** `go/openid/client.go:122-124` authenticates only with `client_secret_post`, and `Config.Validate`
requires a secret (`client.go:186-197`). RFC 9700 §2.5 RECOMMENDS asymmetric client authentication (private_key_jwt,
RFC 7523). The PDP backend and oidf already use it, while generic OIDC providers in pep cannot.

**Acceptance criteria.**
- go/openid supports `private_key_jwt` with a key given as a signing function (keys.md). It is chosen when the provider's metadata lists it and a key is configured. Tests named after RFC 7523 §2.2 and RFC 9700 §2.5.

### G10 → TASK-372 [LOW] idpd Authenticator: the challenge comes only from the IDP-Dienst (related finding, parity with Rust)
**Description.** `Authenticator.Authenticate` (`go/idpd/authenticator.go:158-179`) GETs whatever authorization URL
it is handed, for zero-epa the Aktensystem's `Location`, and only then checks the challenge's IDP signature.
ti-directory-client refuses an authorization URL outside its IDP's origin before anything is fetched or signed
(`owner.rs` `to_own_idp`). RFC 9700 has no rule for the Authenticator's role. This is outside the RFC and listed for
parity.

**Acceptance criteria.**
- The authorization URL must have the origin of the IDP-Dienst's `authorization_endpoint` from its signed metadata, or nothing is fetched. Test named after the requirement, and the same rule in ti-idpd-client if it lacks it.
