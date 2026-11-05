---
id: decision-13
title: Format and framework dependencies live in hosts, not base libraries
date: '2026-11-02T20:56:00Z'
status: accepted
---

## Context

The Go consolidation put a YAML import into `oauth/providers`, `idpd` and `oidf`, so every consumer of a base library carried a parser it might not use. `go.mod` requirements apply per module, so a subpackage does not help: a requirement reaches each consumer's module graph, even if it is never linked. The Rust side already keeps such things in hosts.

## Decision

Maintainer, 2026-11-02: a dependency for a file format, a command line or a framework belongs in a host (a command or server), never in a base library. Base libraries take typed configuration; hosts read files.

For Go configuration, the host reads the file, expands `${VAR}`, decodes strictly and passes a typed struct:

```go
cfg := new(oidf.RelyingPartyConfig)
if err := loadYAML(path, cfg); err != nil { ... }
rp, err := oidf.NewRelyingParty(cfg, filepath.Dir(path))
```

- `oidf.NewRelyingPartyFromConfigFile` goes. `baseDir` is a required argument of `oidf.NewRelyingParty`, so a host cannot forget it and resolve key paths against the wrong directory.
- `oauth/providers` takes entries that decode themselves, and no YAML.
- YAML is `go.yaml.in/yaml/v4`, a release candidate accepted by the maintainer, who expects the final release by the time this work is done. It has no dependencies of its own.

## What stays in libraries, deliberately

- `yaml:"..."` struct tags: strings that document the keys, with no import.
- `UnmarshalYAML(func(any) error)` on types that need it (`oidf.Jwk`): standard types only, supported by v4. Scalars use the standard `encoding.TextUnmarshaler` instead.

## Consequences

- About 25 lines are duplicated between the two hosts, `pdp` and `pep/proxy`: a strict file loader and the ordered providers entries. A shared module would cost more than those lines.
- `just check` fails if YAML, or the TI trust path, appears in the module graph of `oauth` or `oidf`.
- Host modules (`pdp`, `pep/proxy`, `epa`, `zaddy`) may carry such dependencies, as may their own packages.
- `oidf` still reads key files itself. That is a separate no-ambient-I/O gap, TASK-89.
