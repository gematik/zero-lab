---
id: decision-25
title: 'A TLS key reference is a URL, so a key can later sit behind a signer'
date: '2026-11-18 21:34'
status: proposed
---
## Context

Rule 29 reads a listener's or peer's private key from a file, `…_TLS_KEY_PATH`. Rule 6 describes a key provider sidecar over a Unix socket where only digests cross, and the private-key rules treat a key as a function. A TLS 1.3 server key can sit behind such a signer: the handshake needs one signature, not the key.

If the configuration names the key by path only, moving it behind a signer later changes the interface of every server.

## Decision

Proposed, not decided. The maintainer chooses between:

1. **A path now.** Rule 29 and the naming scheme keep `…_TLS_KEY_PATH`. A signer, when it comes, adds a variable and a rule of its own.
2. **A URL now.** The key reference is a URL: `file:` today, `unix:` for a signer later. Rule 29 says so, and the variable is named for a reference, not a path.

## Consequences

- Option 1 matches what is built and what the naming rule says of files (`*_PATH`). A later signer means a second way to name a key, and a start-up rule for a deployment that sets both.
- Option 2 keeps one variable for both. It changes the naming table of docs/conventions/naming-and-config.md before the first server implements it, and breaks the rule that a variable holding a file ends in `_PATH`, unless the URL form gets a suffix of its own. Until a signer exists, `unix:` is refused at start.
- Rule 6 is not changed by either: the key provider and what crosses its socket stay as they are.
