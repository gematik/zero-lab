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

//! Whether an address answers as an IDP-Dienst, for a host checking what it reaches.
//!
//! The discovery document's issuer is read without verifying the document's signature: it
//! tells the IDP-Dienst from a gateway or a front page, nothing more. Nothing read here is
//! trusted; [`crate::discovery`] verifies the document before anything uses it.

use base64ct::{Base64UrlUnpadded, Encoding as _};

/// The path below the IDP-Dienst's address that answers a probe: its discovery document.
pub const PATH: &str = "/.well-known/openid-configuration";

/// What a 200 answer at [`PATH`] says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// A discovery document of the IDP-Dienst at the probed address.
    Idp,
    /// A discovery document naming another issuer.
    OtherIssuer(String),
    /// No discovery document.
    NoDiscovery,
}

/// What `body`, answered at [`PATH`] below `base`, says. The document is JSON, or the
/// gematik IDP-Dienst's signed one: a compact JWS whose payload is the JSON.
pub fn answer(base: &str, body: &[u8]) -> Answer {
    let issuer = document(body).and_then(|d| d.get("issuer")?.as_str().map(str::to_owned));
    match issuer {
        Some(issuer)
            if issuer
                .trim_end_matches('/')
                .eq_ignore_ascii_case(base.trim_end_matches('/')) =>
        {
            Answer::Idp
        }
        Some(issuer) => Answer::OtherIssuer(issuer),
        None => Answer::NoDiscovery,
    }
}

fn document(body: &[u8]) -> Option<serde_json::Value> {
    if let Ok(value) = serde_json::from_slice(body) {
        return Some(value);
    }
    let text = core::str::from_utf8(body).ok()?.trim();
    let payload = text.split('.').nth(1)?;
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_discovery_document_names_the_probed_address_as_json_or_signed() {
        let json = br#"{"issuer":"https://idp.example/"}"#;
        assert_eq!(answer("https://idp.example", json), Answer::Idp);
        let jws = format!(
            "eyJhbGciOiJCUDI1NlIxIn0.{}.c2ln",
            Base64UrlUnpadded::encode_string(json)
        );
        assert_eq!(answer("https://IDP.example/", jws.as_bytes()), Answer::Idp);
        assert_eq!(
            answer("https://other", json),
            Answer::OtherIssuer("https://idp.example/".into())
        );
        assert_eq!(
            answer("https://idp.example", b"<html>"),
            Answer::NoDiscovery
        );
        assert_eq!(answer("https://idp.example", b"{}"), Answer::NoDiscovery);
    }
}
