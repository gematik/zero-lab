---
id: TASK-426
title: >-
  hsm-proxy: health goes stale when the token hangs, stays SERVING while ending,
  and rule 31's cases are untested
status: To Do
assignee: []
created_date: '2026-11-25T18:02:00Z'
labels:
  - rust
  - security
dependencies: []
priority: medium
ordinal: 439000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found on 2026-11-25 by reading ti-hsm-proxy's health against servers.md rule 31, the agreed health design of the observability draft (backlog DRAFT-1, 2026-11-22) and zeta-authserver-go's implementation of it (internal/host/health.go). From the code, not reproduced.

What matches: startup and readiness ask grpc.health.v1 for SERVING and liveness only that the socket answers; a background check every HSM_PROXY_HEALTH_INTERVAL_MS keeps the state and probes read it; every session busy counts as serving; the first check runs before the listener serves; exec probes of the binary without a shell; beside a TCP listener the health is on a Unix socket, not a port; over mTLS grpc.health.v1 answers without a client certificate.

What differs:
1. The background check has no bound and the state no age. check() runs HsmProxy::health in spawn_blocking; the wait bounds getting a session, not the PKCS#11 call. A module that hangs stalls the watcher, and grpc.health.v1 keeps the last status, SERVING, for good. zeta-authserver-go bounds a round (3 s) and is not ready when nobody has checked for three intervals.
2. Ending: on SIGTERM the server shuts down gracefully but never reports NOT_SERVING first, so the pod stays in the Service until the listener is gone. The design: not ready at once, live until the end (authserver: Health.End).
3. HsmProxyService.HealthCheck asks the token on every call and takes a session for it, instead of reading the kept state (rule 31: a probe makes no call to a dependency). It also returns version and hsm_info to whoever reaches a Unix or accepted-plaintext listener; the fields are the interface's (A_28829), so this stays and is recorded as such.
4. Rule 31's tests are missing: with the token stopped the sidecar turns not ready and stays alive; with every session busy it stays ready; a probe answers within its timeout while the token hangs. Only the serving case is tested (task_389_the_sidecars_health_is_probed_over_its_socket).
5. The images declare no HEALTHCHECK, though hsm-proxy health ready exists for it (draft: one command for Kubernetes, Docker and compose; the authserver's image declares it).
Already a task: a log line and metrics on every change of health (TASK-405).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A check round is bounded, and a state older than three intervals reports NOT_SERVING; a test with a hanging token shows the probe answering within its timeout and turning not ready
- [ ] #2 On SIGTERM grpc.health.v1 reports NOT_SERVING before the listener closes, and health live keeps passing until the process ends
- [ ] #3 HealthCheck of the interface answers from the kept state without taking a session
- [ ] #4 Tests named after rule 31: token stopped, not ready and alive; every session busy, ready
- [ ] #5 Dockerfile and Dockerfile.simulator declare HEALTHCHECK with hsm-proxy health ready
<!-- AC:END -->
