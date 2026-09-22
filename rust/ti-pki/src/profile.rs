//! Named validation profiles for the common TI use cases (smb-aut, idp-sig,
//! epa-vau-aut, zeta-guard-aut) and their selection. A profile states the
//! certificate types it accepts, its revocation strictness and optionally the
//! admission role that identifies it. Automatic selection prefers a profile
//! matched on its role over one that merely owns the type, and reports an
//! ambiguous or unclaimed certificate as such rather than guessing.
