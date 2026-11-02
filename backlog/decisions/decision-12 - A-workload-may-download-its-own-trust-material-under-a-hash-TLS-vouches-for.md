---
id: decision-12
title: A workload may download its own trust material, under a hash TLS vouches for
date: '2026-11-02T18:20:00Z'
status: accepted
---

## Context

docs/design/servers.md had trust material reach a workload only through mounted files from a producer. A standalone image has no producer, so it could not verify the IDP-Dienst at all.

## Decision

Maintainer, 2026-11-02: go/gemidp gets a second source, FetchingTrust, and the mounted bundle stays for air-gapped sites. A client configures exactly one. The download runs at start and in the background, never on a login, from fixed hosts per environment, with redirects refused. Everything downloaded passes the checks a bundle passes.

A signature over plain HTTP cannot say a list is the newest, and the memory of the newest seen ends with the process, so a replayed older list would otherwise stand until its NextUpdate, weeks away. So a list is taken only under the SHA-256 the HTTPS host publishes (A_30044).

## Consequences

- A standalone image needs no mount, and needs outbound access to the environment's TSL and CRL hosts.
- TLS now takes part in freshness, though not in authenticity: a compromise of the HTTPS host or of a CA it chains to allows a replay until NextUpdate, not a forged list.
- A workload that loses its route refuses certificates after 24 h, or earlier at the list's NextUpdate.
