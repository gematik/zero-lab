//! The `GEM.RCA<n>` trust anchors compiled into the crate, as the exact DER gematik
//! publishes. Everything else in a trust store earns its place by chaining to one of
//! them. If gematik rotates an anchor, the file changes and the crate is rebuilt;
//! operators who need a different anchor set it on a
//! [`TrustConfig`](crate::TrustConfig) instead.
//!
//! The TEST-ONLY anchors exist only with the `dangerous-nonprod` feature, so a
//! production build contains no non-production trust material.

/// GEM.RCA8, the production anchor.
pub const GEM_RCA8: &[u8] = include_bytes!("anchors/GEM.RCA8.der");

/// GEM.TSL-CA3, the production TSL-Signer-CA. The TSL's detached signature is verified
/// against it, independently of the root store: the TSL-Signer-CA is a SubCA under
/// GEM.RCA4, but taking it as its own anchor lets a TSL be verified without the roots.
pub const GEM_TSL_CA3: &[u8] = include_bytes!("anchors/GEM.TSL-CA3.der");

/// GEM.TSL-CA28 TEST-ONLY, the TSL-Signer-CA of the test, reference and development
/// environments.
#[cfg(feature = "dangerous-nonprod")]
pub const GEM_TSL_CA28_TEST_ONLY: &[u8] = include_bytes!("anchors/GEM.TSL-CA28-TEST-ONLY.der");

/// GEM.RCA7 TEST-ONLY, the anchor of the reference and development environments.
#[cfg(feature = "dangerous-nonprod")]
pub const GEM_RCA7_TEST_ONLY: &[u8] = include_bytes!("anchors/GEM.RCA7-TEST-ONLY.der");

/// GEM.RCA8 TEST-ONLY, the anchor of the test environment.
#[cfg(feature = "dangerous-nonprod")]
pub const GEM_RCA8_TEST_ONLY: &[u8] = include_bytes!("anchors/GEM.RCA8-TEST-ONLY.der");

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    use crate::Timestamp;

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
    fn gem_rca8_fingerprint() {
        assert_fingerprint(
            GEM_RCA8,
            "21:58:F5:B9:C0:17:10:FA:F6:8A:F8:C7:EB:A3:DA:5D:C5:6A:62:D1:29:10:38:CC:A7:A2:7B:7A:6E:BD:13:86",
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

    #[test]
    fn tsl_signer_anchor_is_a_subca_not_a_root() {
        let cert = crate::Certificate::from_der(GEM_TSL_CA3).unwrap();
        assert_eq!(cert.subject_cn(), "GEM.TSL-CA3");
        assert!(cert.issuer_cn().starts_with("GEM.RCA"));
        // A date inside the validity of the real cross certificates (2026-06-01).
        let walk = crate::roots::load(&crate::TrustConfig::preset_prod(), Timestamp(1_780_272_000));
        let store = walk.unwrap().store();
        assert!(store.by_ski(cert.subject_key_id().unwrap()).is_none());
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
}
