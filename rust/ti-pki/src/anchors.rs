//! The trust anchors compiled into the crate, as the exact DER gematik publishes: the
//! `GEM.RCA<n>` roots, which everything else in a trust store earns its place by
//! chaining to, and the `GEM.TSL-CA<n>` TSL signer CAs, which a TSL's signer must be
//! issued by (GS-A_4640, `spec/tsl-xmldsig` TSLSIG-030). If gematik rotates an anchor, the file changes and the crate is rebuilt;
//! operators who need a different anchor set it on a
//! [`TrustConfig`](crate::TrustConfig) instead.
//!
//! The TEST-ONLY anchors exist only with the `dangerous-nonprod` feature, so a
//! production build contains no non-production trust material.

/// GEM.RCA7, the production anchor: a P-256 root, so the roots walk starts without
/// brainpool, and GEM.RCA8 (the anchor before it) vouches for its key with a cross
/// certificate.
pub const GEM_RCA7: &[u8] = include_bytes!("anchors/GEM.RCA7.der");

/// GEM.RCA8, a brainpool root; the production anchor before [`GEM_RCA7`], which it
/// cross-certifies.
pub const GEM_RCA8: &[u8] = include_bytes!("anchors/GEM.RCA8.der");

/// GEM.RCA7 TEST-ONLY, the anchor of every non-production environment.
#[cfg(feature = "dangerous-nonprod")]
pub const GEM_RCA7_TEST_ONLY: &[u8] = include_bytes!("anchors/GEM.RCA7-TEST-ONLY.der");

/// GEM.RCA8 TEST-ONLY, a brainpool root; the test environment's anchor before
/// [`GEM_RCA7_TEST_ONLY`].
#[cfg(feature = "dangerous-nonprod")]
pub const GEM_RCA8_TEST_ONLY: &[u8] = include_bytes!("anchors/GEM.RCA8-TEST-ONLY.der");

/// GEM.TSL-CA3, the TSL signer CA of production, issued by GEM.RCA4; valid until
/// 2028-05-25.
pub const GEM_TSL_CA3: &[u8] = include_bytes!("anchors/GEM.TSL-CA3.der");

/// GEM.TSL-CA28 TEST-ONLY, the TSL signer CA of the reference, test and development
/// environments, issued by GEM.RCA4 TEST-ONLY; valid until 2028-04-06.
#[cfg(feature = "dangerous-nonprod")]
pub const GEM_TSL_CA28_TEST_ONLY: &[u8] = include_bytes!("anchors/GEM.TSL-CA28-TEST-ONLY.der");

/// The TSL signer CAs of production. When gematik announces a new one in the TSL (a
/// `TSLServiceCertChange` service, which verification reports as
/// [`TslCode::TslAnchorAnnounced`](crate::tsl_signature::TslCode::TslAnchorAnnounced)),
/// it is added here; the old one stays until it expires.
pub const TSL_SIGNER_CAS_PROD: &[&[u8]] = &[GEM_TSL_CA3];

/// The TSL signer CAs of the reference, test and development environments; as
/// [`TSL_SIGNER_CAS_PROD`].
#[cfg(feature = "dangerous-nonprod")]
pub const TSL_SIGNER_CAS_NONPROD: &[&[u8]] = &[GEM_TSL_CA28_TEST_ONLY];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    // Fingerprints from `openssl x509 -inform DER -fingerprint -sha256` over the
    // base64 constants in go/gempki/anchors.go; a wrong or swapped file fails here.
    fn assert_fingerprint(der: &[u8], expected: &str) {
        let actual = Sha256::digest(der)
            .iter()
            .fold(String::new(), |mut hex, b| {
                write!(hex, "{b:02X}").unwrap();
                hex
            });
        assert_eq!(actual, expected.replace(':', ""));
    }

    #[test]
    fn gem_rca7_fingerprint() {
        assert_fingerprint(
            GEM_RCA7,
            "30:4F:0D:89:71:53:5A:81:13:DE:67:5C:9C:4E:05:38:2A:5B:C6:7E:5D:4C:B8:32:A9:4B:A9:8F:D9:A3:65:51",
        );
    }

    /// The anchor changed from GEM.RCA8 to GEM.RCA7; the old anchor's cross certificate
    /// for RCA7 carries the new anchor's key, so trust carries over rather than being
    /// taken on faith a second time.
    #[cfg(feature = "brainpool")]
    #[test]
    fn gem_rca8_vouches_for_gem_rca7() {
        use crate::Certificate;
        use der::Encode;

        let (_, _, cross) = crate::algorithms::tests::prod_root("GEM.RCA8");
        let cross = Certificate::from_der(&cross.unwrap().to_der().unwrap()).unwrap();
        // 2026-06-01, inside the cross certificate's validity.
        let now = crate::Timestamp(1_780_272_000);
        crate::roots::verify_cross_signed(
            &Certificate::from_der(GEM_RCA8).unwrap(),
            &cross,
            &Certificate::from_der(GEM_RCA7).unwrap(),
            now,
            crate::algorithms::DEFAULT,
        )
        .unwrap();
    }

    #[test]
    fn gem_rca8_fingerprint() {
        assert_fingerprint(
            GEM_RCA8,
            "21:58:F5:B9:C0:17:10:FA:F6:8A:F8:C7:EB:A3:DA:5D:C5:6A:62:D1:29:10:38:CC:A7:A2:7B:7A:6E:BD:13:86",
        );
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn gem_rca7_test_only_fingerprint() {
        assert_fingerprint(
            GEM_RCA7_TEST_ONLY,
            "B5:4E:52:69:14:07:56:B2:AC:15:37:8C:F7:00:FA:BB:BD:A8:22:F8:A4:FB:FC:7D:6F:4B:DA:9B:E7:CA:28:35",
        );
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn gem_rca8_test_only_fingerprint() {
        assert_fingerprint(
            GEM_RCA8_TEST_ONLY,
            "D4:E6:2B:45:8C:84:66:91:90:0C:07:D2:1A:70:C0:94:27:EF:E7:6E:73:33:C3:91:FB:C4:51:67:FC:79:3F:94",
        );
    }

    #[test]
    fn gem_tsl_ca3_fingerprint() {
        assert_fingerprint(
            GEM_TSL_CA3,
            "E2:99:2D:C2:92:F6:AA:8D:9E:46:2A:77:23:F5:4C:16:28:53:B4:05:6C:27:72:60:B8:2C:E5:89:21:40:84:48",
        );
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn gem_tsl_ca28_test_only_fingerprint() {
        assert_fingerprint(
            GEM_TSL_CA28_TEST_ONLY,
            "43:85:3A:0E:92:BF:D6:E9:E9:9F:02:C1:D1:65:A6:88:AA:94:F0:DF:74:D8:EA:0D:DF:84:9E:CD:01:BE:1D:6A",
        );
    }
}
