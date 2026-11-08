---
id: TASK-246
title: 'Rust: ti-idpd-client and ti-directory-client, the directory without ti-idpd'
status: Done
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-08T08:54:00Z'
labels:
  - ti-idpd
  - ti-directory
  - architecture
dependencies:
  - TASK-245
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 262000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: product clients are named ti-<product>-client, and no product client depends on another; what one needs from another product comes in through a trait that ti-client implements. ti-directory today uses ti-idpd's http types (exchange.rs, request.rs, token.rs, keycloak.rs, owner.rs), its authenticator for the owner login (owner.rs) and its Env and Idp (lib.rs). The FHIR-Directory is its own product.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-idpd is renamed ti-idpd-client and ti-directory ti-directory-client: crate names, directories, docs, traceability and fuzz targets
- [x] #2 ti-directory-client has its own async transport trait and does not depend on ti-idpd-client
- [x] #3 ti-directory-client takes its IDP-Dienst token through a trait (an access token valid for the next request, and a call when the directory refuses it with 401 so it is not handed out again, followed by one retry)
- [x] #4 the host side implements that trait over ti-idpd-client and refreshes the token before it expires; a test proves the directory retries once after a refused token
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Renamed ti-idpd -> ti-idpd-client and ti-directory -> ti-directory-client (git mv): workspace members and dependencies, Justfile (wasm32, core-deps, check-changed, fuzz recipes now fuzz-ti-idpd-client and fuzz-ti-directory-client), rust/docs, mutation-scores.toml, ReleaseNotes Unreleased, fuzz crates and their lock files (regenerated offline), traceability tables (blessed), READMEs, spec/pki-path/README.md, go/idpd comments, naming-and-config.md (a product client's -client suffix is not part of the shared Go/Rust name).

ti-directory-client: own http module (async Transport, no Send), depends on ti-types instead of ti-idpd-client; Directory::new(base_url, idp_url), idp_url(); owner keeps start/authorization_url/sign_in(redirect_url: &str)/token, owner::login and Login removed; Error::Idpd replaced by Error::Token(Box<dyn Error + Send + Sync>). tokens::Tokens (&self, async, no Send) and tokens::send: bearer from Tokens, a 401 reports the token as refused and the request goes once more (tests/tokens.rs, rfc_6750_3_1_...). ti-cli: commands/owner_login.rs joins the directory's steps with ti-idpd-client's authenticator (login), OwnerTokens implements Tokens over it (renews 60 s before expiry, drops a refused token; unit tests); http::Logged implements the directory's Transport; login_card goes through OwnerTokens. The guard test login_stops_at_the_directorys_redirect_when_it_is_not_the_idps moved to ti-cli with its name.

Time and CertificateTrust (decisions 8-10): ti-idpd-client's authenticate, discovery::parse, challenge::parse take now: impl Fn() -> Timestamp; jwz gets it through a private clock::Now adapter implementing jwz::jwt::Clock (comment says it goes once jwz takes a function). ti-directory-client reads no time any more (its only use was passing now to ti-idpd). ti-cli passes Timestamp::now; jwz SystemClock reads in idpd.rs and directory.rs are gone. trust::CertificateTrust::check is async (no Send, reason noted, &T impl kept); discovery::parse became async because it asks the check; authenticate takes &C: CertificateTrust (async traits are not dyn-compatible). ti-cli's IdpTrust awaits the validator instead of block_on, loaded material in a OnceCell so no RefCell borrow is held across an await. New tests: an_asynchronous_trust_check_is_awaited, each_token_is_judged_at_the_time_it_arrives.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-idpd and ti-directory renamed to ti-idpd-client and ti-directory-client. The directory has its own transport and takes its tokens through tokens::Tokens, implemented by ti-client (OwnerTokens), with one retry after a refused token; time as a function; CertificateTrust async. Naming doc updated.
<!-- SECTION:FINAL_SUMMARY:END -->
