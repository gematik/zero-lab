---
id: TASK-250
title: 'ti-client: commands as a synchronous API, ti-cli a thin front end'
status: Done
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-08T08:54:00Z'
labels:
  - ti-client
  - ti-cli
  - architecture
dependencies:
  - TASK-249
  - TASK-248
  - TASK-246
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 266000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: the command-line tool and the Tauri app run the same operations, so the operations live in ti-client and return the engines' model types; ti-cli only parses arguments, reads its configuration and prints. A desktop app depending on ti-cli would pull in clap and terminal output.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each ti command's operation is a function of ti-client returning an engine's model type or a typed result; ti-cli calls it and prints
- [x] #2 ti-cli's output, exit codes and schemas are unchanged
- [x] #3 ti-client does not depend on clap or on terminal output
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Group pki (2026-11-07): the operations of pki verify, verify-signature, inspect, tsl show/verify/bundle/export, roots list/bundle, trust export, pkcs12 convert, identity inspect/sign and the IDP certificate check are in ti-client: trust::Session (from ti-cli trust.rs, over ti_client::Dirs; warnings through a closure, TSL state lines through the client's Observer), pki::{verify, inspect, signature, tsl, roots, bundle, export}, pkcs12, identity (card key behind a private trait, Identity::on_card takes the Konnektor), idp_trust (the session opened by a closure once needed, generic over the front end's error), input, peer, text::span. Results derive Serialize in the shape of the JSON; ti-cli wraps them with the schema field (serde flatten) and renders. ti_client::Error grew the variants ti-cli maps one to one (From<ti_client::Error> for CliError). cache clear already called ti_client::file_cache::clear; unchanged. ti-client has a traceability table now. Outputs of 37 offline invocations (text, markdown, JSON, stderr, exit codes) compared before and after: identical. Left for later groups or tasks: product rules now in ti-client rather than ti-pki (TSLDET-023 at-time loader, the AUT key-usage rule), the profile directory resolved before environment detection in verify.

Group pki, follow-up (coordinator's ruling on decision 3): the rules ti-client had taken over from ti-cli are in ti-pki now and ti-client only calls them: load::AtTime (TSLDET-023), load::read_back / verify_read_back / NoNetwork (TSLDET-015, TSLSIG-053), Tsl::verify_file (TSLDET-005, 020, 022, 023, TSLSIG-053; FileVerdict keeps the sequence when a later step fails, as tsl verify's JSON did), cert_type::is_authentication (PROF-002). Tests named after the rules in ti-pki; outputs compared again, identical.

Group connector (2026-11-07): the operations of connector config list/use/show/test/new/edit/set/pin, get info/services/cards/certificates/status/identities/expiration, describe card/certificate, verify/change pin, verify certificate/signature, sign, encrypt, decrypt, comfort and export are in ti_client::connector: store (.kon files as the Go ti keeps them), Session/connect/card_user (HBA user IDs in private files), cards, documents (documents as bytes), setup (view, validate, refuse, test). They return the new ti_connector_client::model (Serialize behind feature serde). Konnektor rules the CLI applied moved to ti-connector-client: PinType::choose, has_user_sessions (TAB_KON_510), is_restricted, IDENTITY_CARDS, Certificates::telematik_id, SignatureFormat::for_document/to_verify, media_type, short_text, edit::validate, edit::pins, model::Severity (TAB_KON_503). A wait at the card terminal reaches the front end through a closure called with a Wait; no PIN passes through ti-client. ti_client::Error gained ConnectorConfig, CardRestricted, PinType, Refused, Write, mapped to the same CliError kinds. The wizard and editor prompts stay in ti-cli. 183 captured invocations (61 commands x text/markdown/JSON) against the fake Konnektor: identical before and after. A user ID without system randomness is Error::Randomness instead of a panic.

Group idp (2026-11-07): the operations of idpd authenticate and directory login owner/search/holder/service/ti-provider are in ti-client: idpd::authenticate with idpd::Card (the identity's BP256R1 signer; built before the transport, so the error order is kept), directory::{card, search, regservice, client_credentials} returning directory::Login, and directory::owner (the owner login joining the directory's steps and the IDP-Dienst flow, OwnerTokens implementing ti-directory-client's Tokens; moved from ti-cli with its tests). The products' projections are new models: ti_idpd_client::model::{IdpInfo, CertificateInfo, ChallengeInfo} and ti_directory_client::model::{Token, DirectoryInfo, Credential}, Serialize behind a new serde feature each; the search rule (aud names /search) is Token::for_search with Directory::search_url and ti_directory_client::Warning::SearchNotInAudience. The transport stays a parameter so ti-cli keeps its -v decorator. ti_client::Error gained Idpd and Directory, mapped to CliError::Idpd and Directory. 264 captured invocations (88 x text/markdown/JSON, with -vv, --token and error paths) against the integration tests' fake IDP-Dienst, directory and Keycloak: identical before and after.

Group rest (2026-11-08): R1: ti-client makes every transport from the Client's settings and tells a Watcher on the Client (ti_client::watch: Sending/Done with method, URL, SOAP operation, status, bodies, time; Konnektor bodies with the UserId masked by ti_connector_client::Request::redacted_body, never a credential) about each request to the Konnektor, the IDP-Dienst and the FHIR-Directory; Client::idp/connector return Watched transports, connector::setup::test takes the Client; ti-cli's Logged decorators are gone and its watcher writes the same -v/-vv lines. The operations stay generic over the transport for test doubles. R2: Identity::from_card reads the card's C.AUT through the connector operations. R4: ti_client::probe (endpoints, Agents per TLS profile, run with progress through a closure, available, Report); the judgements and the endpoint catalog stay in ti-client as the host's connectivity (no trust taken from what is read; the catalog spans every product). ti-cli no longer depends on ureq, ti-tls, rustls (dev only) or sha2 (dev only). profile list/delete (ti_client::profile) and pki profiles (ti_client::pki::profiles over ti_pki::model::{ValidationProfile, TypeRequirements, TslCas}); sweep: Loaded::sha256, store::remove_copy. Outputs compared before and after every commit: 361 offline files and 1085 fake-driven files (connector, idp, probe; -v/-vv, error orders) identical, apart from a TLS fake's random reset message. What remains in ti-cli is front-end work: argument parsing (cli, net, peer), configuration (which profile, bases and .kon are in effect: profile.rs, paths.rs, connector.rs), reading inputs (input.rs), prompting (prompt.rs, the connector config wizards and editor loop, R3), printing (output/, each command's report wrapper and views, output files, the probe's live table, the -v lines of http.rs), the mapping of ti_client::Error to kinds and exit codes (error.rs), and the CLI's self-description (version, agent, schema).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Every ti command's operation is a synchronous function of ti-client returning a product model or a typed result; ti-cli parses arguments, reads configuration, prompts and prints. ti-client builds the transports and reports requests to a hook on the Client; probe's network checks are in ti_client::probe with progress through a closure. Product views in the model modules of ti-pki, ti-connector-client, ti-idpd-client and ti-directory-client. ti-cli no longer depends on ureq or ti-tls. Output, exit codes and schemas unchanged (361 offline and 1085 fake-driven outputs compared). Findings: TASK-262 to 268.
<!-- SECTION:FINAL_SUMMARY:END -->
