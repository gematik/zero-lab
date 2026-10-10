---
id: decision-4
title: Speed and startup before binary size
date: '2026-10-09 13:55'
status: accepted
---
## Context

ti is about 6 MB; the WebAssembly build has a size budget. Optimizing for size (opt-level "z", wasm-opt -Oz) costs runtime speed and startup.

## Decision

Speed and startup come before binary size: release and wasm profiles stay at opt-level 3, wasm-opt runs -O3. Binary size work is dropped.

## Consequences

just wasm-size enforces a budget (2.0 MB raw, 700 KB gzip) without trading speed for it.
