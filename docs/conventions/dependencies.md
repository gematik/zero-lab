# Dependencies: as few as possible, only stable, evaluated, secure

Every dependency is code we ship and vouch for without having written it. The default
answer to a new dependency is no.

1. **Standard library first**, then the language's semi-official extensions (the
   profiles name them). A few dozen lines of our own, tested, beat a dependency for
   anything that is not cryptography or a parser of hostile input with a serious
   implementation available.
2. **Reuse before adding.** If a dependency already in the tree does the job, use it
   rather than a second library for the same purpose (two base64s, two XML parsers, two
   JOSE libraries).
3. **Only stable, evaluated, maintained libraries.** The profiles name the preferred
   ones (for example RustCrypto, rustls, ring, dalek, serde; Go's standard library). A
   candidate must be widely used, actively maintained by more than one person, have a
   security history we can read (advisories, audits, fuzzing), and a released,
   non-pre-release version. A pre-release or otherwise immature dependency is allowed
   only when nothing stable exists, and is then listed as a known compromise (the
   development guide of the workspace) with the trigger that removes it.
4. **Never hand-roll cryptography for operations on secrets.** Signature verification
   and other operations on public data use the evaluated standard implementation. Custom
   constant-time code exists only where no evaluated implementation does, and is then
   formally verified ([testing](../design/testing.md#verification-and-tooling)), as jwz's
   is.
5. **Minimal surface.** Only the features used (no default features by habit). Weigh the
   transitive tree, not only the direct dependency. Runtime glue (HTTP clients,
   executors, platform APIs) stays behind opt-in features or in adapter units, never in
   a core.
6. **Latest versions.** Keep the latest toolchain and the latest release of every
   dependency; never downgrade for compatibility. A fixed advisory is a release blocker.
7. **Ask first.** Adding a dependency, enabling a feature that pulls new crates or
   modules, or swapping one library for another needs the maintainer's approval, with the
   reason, the transitive cost, and the alternatives considered. Record the reason next to
   the dependency (the profiles say where).
8. **Removal is a feature.** When a dependency's use shrinks to something small, replace
   it and delete it.

The supply-chain checks of each workspace (licences, advisories, bans, sources, audits)
stay green; the profiles name them. The licences allowed for dependencies are those of
the workspace's licence policy; the repository's own code is EUPL-1.2.
