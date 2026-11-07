/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The response model: read-only projections of a completed Authenticator-Modul flow as
//! the front ends show it. The types only map: no I/O, no request. With the `serde`
//! feature they serialize to the JSON the `ti` CLI publishes, which its schemas
//! (`ti-cli/schemas/idpd-authenticate.json`, `directory-login.json`) describe; the shape
//! is declared here, the format is the host's.

use ti_pki::Certificate;

use crate::Idp;
use crate::authenticator::{Authenticated, CheckedCertificate};
use crate::trust::Checked;

/// The IDP-Dienst a flow ran against, as its discovery document named it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct IdpInfo {
    /// Where the flow found it.
    pub base_url: String,
    /// `issuer` of its discovery document.
    pub issuer: String,
    /// `authorization_endpoint` of its discovery document.
    pub authorization_endpoint: String,
    /// The discovery document's and `PuK_IDP_SIG`'s certificates.
    pub certificates: Vec<CertificateInfo>,
}

impl IdpInfo {
    /// `idp` as `authenticated` found it.
    pub fn new(idp: &Idp, authenticated: &Authenticated) -> IdpInfo {
        let metadata = &authenticated.discovery.metadata;
        IdpInfo {
            base_url: idp.base_url().to_owned(),
            issuer: metadata.issuer.clone(),
            authorization_endpoint: metadata.authorization_endpoint.clone(),
            certificates: authenticated
                .certificates
                .iter()
                .map(CertificateInfo::from)
                .collect(),
        }
    }
}

/// One of the IDP's certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CertificateInfo {
    /// `puk_disc_sig` or `puk_idp_sig`.
    pub key: &'static str,
    /// Its subject; empty if it does not parse.
    pub subject: String,
    /// SHA-256 of the DER, upper-case hex pairs joined by colons; empty if it does not
    /// parse.
    pub sha256: String,
    /// Checked against the TSL and valid; false when not checked.
    pub verified: bool,
}

impl From<&CheckedCertificate> for CertificateInfo {
    fn from(c: &CheckedCertificate) -> Self {
        // The flow parsed both certificates before it used their keys, so the empty
        // fallback is never what a completed flow reports.
        let (subject, sha256) = Certificate::from_der(&c.der)
            .map(|cert| (cert.subject().to_string(), cert.fingerprint_sha256()))
            .unwrap_or_default();
        CertificateInfo {
            key: c.which.as_str(),
            subject,
            sha256,
            verified: c.checked == Checked::Verified,
        }
    }
}

/// Claims of the IDP's challenge, for the record: what the relying party asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ChallengeInfo {
    /// `client_id`: the relying party.
    pub client_id: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
    /// `redirect_uri`: where the code goes.
    pub redirect_uri: Option<String>,
}

impl From<&Authenticated> for ChallengeInfo {
    fn from(authenticated: &Authenticated) -> Self {
        let claim = |name: &str| {
            authenticated
                .challenge_claims
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        };
        ChallengeInfo {
            client_id: claim("client_id"),
            scope: claim("scope"),
            redirect_uri: claim("redirect_uri"),
        }
    }
}
