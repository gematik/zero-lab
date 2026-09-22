//! Assembly of a [`TrustStore`](crate::TrustStore) from gematik's roots.json,
//! either the copy compiled into the crate or a freshly downloaded one. Every
//! candidate root must chain back to the environment's anchor through the
//! A_28419 cross-certificate protocol: seven checks per candidate, implemented
//! step by step so the code can be read against gemSpec_PKI. The walk follows
//! the anchor's successors forward and its predecessors backward, so a
//! download can only ever add roots that chain to the anchor.
