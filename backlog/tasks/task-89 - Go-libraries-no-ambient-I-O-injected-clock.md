---
id: TASK-89
title: 'Go libraries: no ambient I/O, injected clock'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-05T21:29:00Z'
labels:
  - go
dependencies: []
references:
  - docs/architecture.md
  - go/docs/design.md
priority: medium
ordinal: 87000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep/proxy and bff/gateway read environment variables themselves; about 40 time.Now() calls outside tests in decision code (goals 3 and 6).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 configuration read only in cmd/; decision code takes the time as a parameter or func() time.Time
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done on refactor/go-no-ambient-io (4960c15c). Env reads moved to cmd/: PDP_OPENID_PROVIDERS_PATH (pdp.LoadConfigFile param), PEP_ROUTES_PATH/PEP_API_UPSTREAM/PEP_WEBAPP_UPSTREAM (proxy.RouteSources), EPA_TI_BIN (ti.NewBinary(path)), OIDF API_KEY (RelyingPartyConfig.APIKey, oidf.Kind(apiKey, …), pdp.Config.OIDFAPIKey; api_key_path removed at the maintainer's request). Clocks injected in kv memory store, openid, idpd, oidf, pep, pep/proxy, pdp/authzserver, epa.
Rulings: ${VAR} placeholder expansion in config files stays (documented file format). Left on the wall clock: log durations (httputil), the kv TTL conversions in kv.ReplayCache and pdp recordNonce/session_store_kv (they map an absolute expiry to the store's relative TTL, which the store judges by its own clock), mockidp, metsubushi main.
Breaking: pep.OpenSessionCookie(now), pep.Context.Now(), epa.ProvidePNFunc(id, now), ti.NewProber(runner, now), oidf.Kind(apiKey, built), pdp.LoadConfigFile(path, providersPath).

OIDF key renamed per the maintainer: PDP_OIDF_DEV_API_KEY (zero-pdp), PEP_OIDF_DEV_API_KEY (zero-pep-proxy); naming-and-config.md documents why it stays a value (dev federation only, sent only to *.dev.gematik.solutions).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Libraries read no environment: PDP_OPENID_PROVIDERS_PATH, the PEP route variables, EPA_TI_BIN and the OIDF development key (PDP_OIDF_DEV_API_KEY / PEP_OIDF_DEV_API_KEY, a documented exception to secrets-from-files) are read in cmd/. Decision code takes an injected clock in kv, openid, idpd, oidf, pep, pep/proxy, pdp/authzserver and epa. Breaking APIs need new releases of pep, pep/proxy, zaddy, epa, oidf and pdp. Merged into main as 4960c15c and 9b937a27.
<!-- SECTION:FINAL_SUMMARY:END -->
