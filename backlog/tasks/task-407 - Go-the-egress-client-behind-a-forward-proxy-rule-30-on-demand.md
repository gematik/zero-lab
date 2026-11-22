---
id: TASK-407
title: 'Go: the egress client behind a forward proxy (rule 30), on demand'
status: Done
assignee: []
created_date: '2026-11-22 12:22'
updated_date: '2026-11-22 16:47'
labels:
  - go
  - servers
dependencies:
  - TASK-384
references:
  - docs/design/servers.md
priority: low
ordinal: 420000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Split from TASK-384 (2026-11-22, maintainer): the egress client honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY, https through CONNECT only, no extra CA for egress, proxy credentials from a *_PATH file (a proxy URL with user information is refused), and the proxy in effect reported (rule 7). No deployment of ours uses a forward proxy today; build it when an operator requires one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The egress client of TASK-384 goes through a forward proxy as rule 30 says, with tests for CONNECT, refused user information in the URL and NO_PROXY
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-22: built in go/egress (maintainer asked for it now): egress.Proxy (HTTPS, HTTP, NoProxy, Credentials), ProxyFromEnv (HTTPS_PROXY/HTTP_PROXY/NO_PROXY, lower case as fallback, user information refused, value never quoted), ParseProxyCredentials, ProxyFromHost(getenv, readFile, <PREFIX>_EGRESS_PROXY_CREDENTIALS_PATH), Options.Proxy (nil: direct; net/http's ProxyFromEnvironment no longer used), Proxy.String for the start log. https by CONNECT only, the origin verified under the web profile, no proxy CA; revocation fetches take the same proxy. Hosts: zero-pep-proxy (PEP_EGRESS_PROXY_CREDENTIALS_PATH, CONFIG.md) and zero-epa (EPA_EGRESS_PROXY_CREDENTIALS_PATH). zaddy is wired after TASK-379 merges (its branch builds the egress client there). Tests: TestServerRule30_HTTPSGoesThroughTheProxyByCONNECTOnly, _PlainHTTPGoesThroughTheProxyOnlyForSelfVerifyingData, _AProxyURLWithUserInformationIsRefused, _NoProxyHostsAreReachedDirect, _TheProxyIsReportedWithoutItsCredentials, _ATLSInterceptingProxyFailsTheHandshake, _ProxyCredentialsComeFromAFile.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/egress takes a forward proxy: egress.Proxy built by the host with egress.ProxyFromHost(getenv, readFile, <PREFIX>_EGRESS_PROXY_CREDENTIALS_PATH) from HTTPS_PROXY, HTTP_PROXY and NO_PROXY, passed in Options.Proxy; nil goes direct. https by CONNECT only, the origin verified under the web profile, no proxy CA (an intercepting proxy fails the handshake); plain http, for self-verifying data only, forwarded; a proxy URL with user information refused, its value never quoted; credentials from the file as Basic Proxy-Authorization; Proxy.String logged at start; the revocation fetches take the same proxy. Hosts: zero-pep-proxy (PEP_EGRESS_PROXY_CREDENTIALS_PATH), zero-epa (EPA_EGRESS_PROXY_CREDENTIALS_PATH), zaddy (egress_proxy_credentials_path in the pep block). Seven TestServerRule30_* tests in go/egress and one in zaddy.
<!-- SECTION:FINAL_SUMMARY:END -->
