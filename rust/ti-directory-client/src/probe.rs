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

//! Whether an address answers as the FHIR-Directory, for a host checking what it reaches.
//!
//! Asked for the owner authentication without a token, the directory redirects to an
//! IDP-Dienst's authorization endpoint, which a gateway or a front page does not. The
//! check is looser than [`crate::owner::authorization_url`], which requires the
//! directory's own IDP-Dienst; a probe does not know it.

/// The path below the directory's address that answers a probe; the request must not
/// follow redirects.
pub const PATH: &str = "/owner-authenticate";

/// What an answer at [`PATH`] says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// A redirect to an IDP-Dienst's authorization URL: the directory.
    OwnerAuth,
    /// A redirect elsewhere.
    NoAuthorizationUrl,
    /// No redirect.
    NoRedirect,
}

/// What an answer with `status` and the redirect's `location` says.
pub fn answer(status: u16, location: &[u8]) -> Answer {
    let location = String::from_utf8_lossy(location);
    let authorization = location.starts_with("https://") && location.contains("client_id=");
    match status {
        300..=399 if authorization => Answer::OwnerAuth,
        300..=399 => Answer::NoAuthorizationUrl,
        _ => Answer::NoRedirect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owner_authentication_redirects_to_an_idp() {
        let idp = b"https://idp-ref.app.ti-dienste.de/auth?response_type=code&client_id=GEMx";
        assert_eq!(answer(302, idp), Answer::OwnerAuth);
        assert_eq!(answer(302, b"/login"), Answer::NoAuthorizationUrl);
        assert_eq!(answer(200, b""), Answer::NoRedirect);
    }
}
