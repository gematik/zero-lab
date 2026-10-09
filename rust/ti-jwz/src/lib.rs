//! The gematik TI profiles for jwz, from gemSpec_Krypt V2.50.0: `Profile::ti()` for new
//! components (ES256, ECDH-ES on P-256, A256GCM) and, behind the `legacy` feature,
//! `Profile::ti_legacy()`, which also accepts brainpool for existing interfaces. No RSA,
//! no HMAC. The profiles arrive in milestone 1 stage S5, once jwz has profiles (S3).
#![no_std]
#![forbid(unsafe_code)]
