//! Whether certificates belong to gematik's production TI or to one of its test
//! environments, worked out offline from the compiled-in roots and naming conventions.
//!
//! The answer stops at [`Tier`] on purpose: dev and ref share one trust domain, and ref
//! and test publish the same GEM.RCA TEST-ONLY roots, so inspection cannot separate
//! the three. Pinning the environment further needs that environment's TSL.
//!
//! Non-production roots are compiled in only with the `dangerous-nonprod` feature.
//! Without it, the root and chain phases recognise production only, and non-production
//! certificates are told by their markers.

use core::fmt;

use const_oid::db::rfc4519::O;
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::Name;

use crate::time::Timestamp;
use crate::{Certificate, Tier, TrustConfig, TrustStore, build_chain, roots};

/// The evidence that decided a [`TrustDomainResult`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TrustDomainMethod {
    /// An input certificate is an embedded root.
    RootIdentity,
    /// The first certificate chains to an embedded root through the others.
    Chain,
    /// gematik's naming conventions: TEST-ONLY, NOT-VALID, test hostnames.
    Markers,
}

impl TrustDomainMethod {
    /// `root-identity`, `chain` or `markers`, as in `gempki`.
    pub const fn as_str(self) -> &'static str {
        match self {
            TrustDomainMethod::RootIdentity => "root-identity",
            TrustDomainMethod::Chain => "chain",
            TrustDomainMethod::Markers => "markers",
        }
    }
}

impl fmt::Display for TrustDomainMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One attempted detection phase and how it went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustDomainStep {
    /// The phase.
    pub method: TrustDomainMethod,
    /// What it found.
    pub outcome: String,
}

/// What [`detect_trust_domain`] found: the verdict, the evidence behind it, and every
/// phase tried, so a caller can explain a failure without re-running detection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustDomainResult {
    /// The verdict; `None` means undecidable, never non-production.
    pub domain: Option<Tier>,
    /// The deciding phase.
    pub method: Option<TrustDomainMethod>,
    /// The deciding evidence in words, e.g. `"GEM.RCA8" is a prod trust anchor`.
    pub detail: String,
    /// Every phase tried, in order.
    pub steps: Vec<TrustDomainStep>,
}

impl TrustDomainResult {
    fn step(&mut self, method: TrustDomainMethod, outcome: String) {
        self.steps.push(TrustDomainStep { method, outcome });
    }

    fn decide(mut self, domain: Tier, method: TrustDomainMethod, detail: String) -> Self {
        self.domain = Some(domain);
        self.method = Some(method);
        self.step(method, detail.clone());
        self.detail = detail;
        self
    }
}

/// Works out the trust domain of `certs`, leaf first. Supplying the issuing CA along
/// with the leaf lets the chain phase decide, which is stronger evidence than the
/// markers. The embedded roots are walked as of `now`.
///
/// Three phases, the first hit wins: an input certificate is an embedded root; the
/// leaf chains to one; gematik's naming markers. The marker phase is asymmetric: a
/// TEST-ONLY marker proves non-production, but its absence proves nothing, or any
/// self-signed certificate would pass as production. Production is concluded only
/// from the roots or from a TI revocation host without any non-production marker.
pub fn detect_trust_domain(certs: &[Certificate], now: Timestamp) -> TrustDomainResult {
    let mut result = TrustDomainResult::default();
    let Some((leaf, intermediates)) = certs.split_first() else {
        result.detail = "no certificates supplied".into();
        return result;
    };
    let stores = embedded_stores(now, &mut result);
    for cert in certs {
        for (tier, store) in &stores {
            if store.contains(cert) {
                return result.decide(
                    *tier,
                    TrustDomainMethod::RootIdentity,
                    format!("{:?} is a {} trust anchor", cert.subject_cn(), label(*tier)),
                );
            }
        }
    }
    result.step(
        TrustDomainMethod::RootIdentity,
        "no input certificate is an embedded root".into(),
    );

    for (tier, store) in &stores {
        if let Ok(chain) = build_chain(leaf, intermediates, store)
            && let Some(root) = chain.last()
        {
            return result.decide(
                *tier,
                TrustDomainMethod::Chain,
                format!("chains to {} root {:?}", label(*tier), root.subject_cn()),
            );
        }
    }
    result.step(
        TrustDomainMethod::Chain,
        format!(
            "no chain to an embedded root: the issuer of {:?} was not supplied or is unknown",
            leaf.subject_cn()
        ),
    );
    by_markers(result, certs)
}

fn label(tier: Tier) -> &'static str {
    match tier {
        Tier::Prod => "prod",
        Tier::NonProd => "non-prod",
    }
}

/// The production store and, with `dangerous-nonprod`, the merged ref and test store;
/// a store that cannot be built is recorded as a step and left out.
fn embedded_stores(now: Timestamp, result: &mut TrustDomainResult) -> Vec<(Tier, TrustStore)> {
    let mut stores = Vec::new();
    match roots::load(&TrustConfig::preset_prod(), now) {
        Ok(walk) => stores.push((Tier::Prod, walk.store())),
        Err(e) => result.step(
            TrustDomainMethod::RootIdentity,
            format!("prod roots unavailable: {e}"),
        ),
    }
    #[cfg(feature = "dangerous-nonprod")]
    {
        let mut nonprod = Vec::new();
        for env in [ti_types::Env::Ref, ti_types::Env::Test] {
            match roots::load(&TrustConfig::preset(env), now) {
                Ok(walk) => nonprod.extend(walk.trusted),
                Err(e) => result.step(
                    TrustDomainMethod::RootIdentity,
                    format!("{env} roots unavailable: {e}"),
                ),
            }
        }
        stores.push((Tier::NonProd, TrustStore::new(nonprod)));
    }
    #[cfg(not(feature = "dangerous-nonprod"))]
    result.step(
        TrustDomainMethod::RootIdentity,
        "non-prod roots not compiled in (feature dangerous-nonprod)".into(),
    );
    stores
}

/// gematik's naming conventions for non-production certificates: TEST-ONLY in the
/// common name, NOT-VALID in the organization, `-test`/`-ref` revocation hosts.
const TEST_ONLY: &str = "TEST-ONLY";
const NOT_VALID: &str = "NOT-VALID";

fn by_markers(result: TrustDomainResult, certs: &[Certificate]) -> TrustDomainResult {
    let mut prod_host = None;
    for cert in certs {
        if let Some(marker) = non_prod_marker(cert) {
            return result.decide(Tier::NonProd, TrustDomainMethod::Markers, marker);
        }
        prod_host = prod_host.or_else(|| {
            cert.ocsp_urls()
                .iter()
                .map(|url| host_of(url))
                .find(|host| host.ends_with(".ti-dienste.de"))
        });
    }
    if let Some(host) = prod_host {
        return result.decide(
            Tier::Prod,
            TrustDomainMethod::Markers,
            format!(
                "revocation endpoint {host:?} is a production TI host and no TEST-ONLY marker \
                 is present"
            ),
        );
    }
    let mut result = result;
    result.step(
        TrustDomainMethod::Markers,
        "no TEST-ONLY/NOT-VALID marker and no TI revocation endpoint".into(),
    );
    result
}

fn non_prod_marker(cert: &Certificate) -> Option<String> {
    if cert.subject_cn().contains(TEST_ONLY) {
        return Some(format!(
            "subject CN {:?} carries {TEST_ONLY}",
            cert.subject_cn()
        ));
    }
    if cert.issuer_cn().contains(TEST_ONLY) {
        return Some(format!(
            "issuer CN {:?} carries {TEST_ONLY}",
            cert.issuer_cn()
        ));
    }
    for (role, name) in [("subject", cert.subject()), ("issuer", cert.issuer())] {
        if let Some(o) = organizations(name).find(|o| o.contains(NOT_VALID)) {
            return Some(format!("{role} O {o:?} carries {NOT_VALID}"));
        }
    }
    cert.ocsp_urls()
        .iter()
        .map(|url| host_of(url))
        .find(|host| is_non_prod_host(host))
        .map(|host| format!("revocation endpoint {host:?} is a test host"))
}

fn organizations(name: &Name) -> impl Iterator<Item = String> + '_ {
    name.iter_rdn()
        .flat_map(x509_cert::name::RelativeDistinguishedName::iter)
        .filter(|atv| atv.oid == O)
        .filter_map(|atv| atv.value.decode_as::<DirectoryString>().ok())
        .map(|o| o.value().into_owned())
}

/// The lowercase host of an absolute URL, without port or credentials.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    host.split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// gematik's test hosts (`ocsp-testref.root-ca…`, `download-ref.crl…`,
/// `download-test.tsl…`), without matching a production host that merely contains
/// the letters "test".
fn is_non_prod_host(host: &str) -> bool {
    if !host.ends_with(".ti-dienste.de") {
        return false;
    }
    let label = host.split('.').next().unwrap_or_default();
    ["-testref", "-test", "-ref"]
        .iter()
        .any(|suffix| label.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(result: &TrustDomainResult) -> (Option<Tier>, Option<TrustDomainMethod>, &str) {
        (result.domain, result.method, result.detail.as_str())
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("http://User@OCSP-TestRef.root-ca.ti-dienste.de:8080/ocsp?x"),
            "ocsp-testref.root-ca.ti-dienste.de"
        );
        assert_eq!(host_of("ehca.gematik.de"), "ehca.gematik.de");
        assert!(is_non_prod_host("ocsp-testref.root-ca.ti-dienste.de"));
        assert!(is_non_prod_host("download-ref.crl.ti-dienste.de"));
        assert!(!is_non_prod_host("ocsp.root-ca.ti-dienste.de"));
        assert!(!is_non_prod_host("testing.ti-dienste.de"));
        assert!(!is_non_prod_host("ocsp-test.example.org"));
    }

    #[test]
    fn nothing_to_go_on() {
        let result = detect_trust_domain(&[], Timestamp(0));
        assert_eq!(verdict(&result), (None, None, "no certificates supplied"));
    }

    #[cfg(feature = "brainpool")]
    mod embedded {
        use super::*;
        use crate::cert::tests::{RCA5, SMCB_CA51, fixture};
        use crate::testing::TestPki;

        // Within the validity of the embedded cross certificates (2026-06-01).
        const NOW: Timestamp = Timestamp(1_780_272_000);

        #[test]
        fn prod_by_root_and_by_chain() {
            let (rca10, ..) = crate::algorithms::tests::prod_root("GEM.RCA10");
            assert_eq!(
                verdict(&detect_trust_domain(
                    &[Certificate::from_der(&der::Encode::to_der(&rca10).unwrap()).unwrap()],
                    NOW
                )),
                (
                    Some(Tier::Prod),
                    Some(TrustDomainMethod::RootIdentity),
                    "\"GEM.RCA10\" is a prod trust anchor"
                )
            );
            let tsl =
                crate::tsl::Tsl::parse(include_bytes!("../tests/fixtures/tsl/ECC-RSA_TSL.xml"))
                    .unwrap();
            let ca = tsl
                .intermediate_cas()
                .into_iter()
                .find(|c| c.subject_cn() == "MESIG.SMCB-CA1")
                .unwrap();
            let result = detect_trust_domain(&[ca], NOW);
            assert_eq!(result.domain, Some(Tier::Prod));
            assert_eq!(result.method, Some(TrustDomainMethod::Chain));
        }

        #[test]
        fn test_pki_by_markers_and_the_undecidable() {
            let pki = TestPki::new();
            let result = detect_trust_domain(std::slice::from_ref(&pki.ee_arzt), NOW);
            assert_eq!(
                verdict(&result),
                (
                    Some(Tier::NonProd),
                    Some(TrustDomainMethod::Markers),
                    "subject CN \"Dr. Arzt TEST-ONLY\" carries TEST-ONLY"
                )
            );
            assert_eq!(
                result.steps.len(),
                if cfg!(feature = "dangerous-nonprod") {
                    3
                } else {
                    4
                }
            );

            let rogue = detect_trust_domain(std::slice::from_ref(&pki.rogue_root), NOW);
            assert_eq!(rogue.domain, None);
            assert_eq!(
                rogue.steps.last().unwrap().outcome,
                "no TEST-ONLY/NOT-VALID marker and no TI revocation endpoint"
            );
        }

        #[test]
        fn real_reference_certificates() {
            let (ca, root) = (fixture(SMCB_CA51), fixture(RCA5));
            let ee = fixture(include_str!("../tests/fixtures/admission-1.pem"));
            let by_root = detect_trust_domain(&[root], NOW);
            let by_chain = detect_trust_domain(&[ee, ca], NOW);
            assert_eq!(by_root.domain, Some(Tier::NonProd));
            assert_eq!(by_chain.domain, Some(Tier::NonProd));
            if cfg!(feature = "dangerous-nonprod") {
                assert_eq!(by_root.method, Some(TrustDomainMethod::RootIdentity));
                assert_eq!(by_chain.method, Some(TrustDomainMethod::Chain));
            } else {
                assert_eq!(by_root.method, Some(TrustDomainMethod::Markers));
                assert_eq!(by_chain.method, Some(TrustDomainMethod::Markers));
            }
        }
    }
}
