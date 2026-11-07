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

//! The SMC-B or HBA authentication identity (AUT) a command signs with: from a PKCS#12
//! file, a PEM certificate and key, or a card at the Konnektor, read here and handed to
//! ti-client, which holds it as one [`Identity`] whichever it was.

use jwz::jwa::SignatureAlgorithm;

pub use ti_client::identity::{Identity, SourceKind};

use crate::cli::{ConnectorArgs, GlobalArgs, IdentityArgs, SignAlg};
use crate::connector;
use crate::error::CliError;
use crate::input;
use crate::output::Output;

impl From<SignAlg> for SignatureAlgorithm {
    fn from(alg: SignAlg) -> Self {
        match alg {
            SignAlg::Es256 => SignatureAlgorithm::ES256,
            SignAlg::Bp256r1 => ti_jwz::brainpool::BP256R1,
        }
    }
}

/// The identity `args` name, loaded and ready to sign.
///
/// # Errors
///
/// Reading and decoding errors of the source; [`CliError::IdentityNotFound`] when no AUT
/// certificate with its key is there; [`CliError::KeyUnsupported`] for a key that is not
/// ECDSA on brainpoolP256r1 or P-256.
pub fn load(args: &IdentityArgs, global: &GlobalArgs, out: &Output) -> Result<Identity, CliError> {
    if let Some(path) = &args.p12 {
        let password = input::p12_password(&args.password)?;
        let source = input::read(path)?;
        return Ok(Identity::from_p12(&source.bytes, &source.name, &password)?);
    }
    if let (Some(cert), Some(key)) = (&args.cert, &args.key) {
        let certs = input::read(cert)?;
        let certificates = input::certificates(&certs, "")?
            .into_iter()
            .map(|loaded| loaded.certificate)
            .collect();
        let key = input::read(key)?;
        return Ok(Identity::from_pem(
            certificates,
            &certs.name,
            &key.bytes,
            &key.name,
        )?);
    }
    if let Some(card) = &args.card {
        return from_connector(args.connector.as_deref(), card, global, out);
    }
    // clap requires one of the three.
    Err(CliError::IdentityNotFound("no identity given".into()))
}

/// The identity of `card` at the Konnektor `name` names (none: the selected one).
fn from_connector(
    name: Option<&str>,
    card: &str,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Identity, CliError> {
    let args = ConnectorArgs::for_identity(name);
    let session = connector::open(&args, global, out)?;
    Ok(Identity::from_card(session, card)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_card_alone_names_the_selected_connector() {
        use clap::Parser as _;
        let parse = |args: &[&str]| {
            crate::cli::Cli::try_parse_from(
                ["ti", "identity", "inspect"]
                    .iter()
                    .copied()
                    .chain(args.iter().copied()),
            )
        };
        let Ok(cli) = parse(&["--card", "SMC-B-7"]) else {
            panic!("--card alone is a source");
        };
        let crate::cli::Command::Identity(crate::cli::IdentityCommand::Inspect(args)) = cli.command
        else {
            panic!("identity inspect");
        };
        assert_eq!(args.card.as_deref(), Some("SMC-B-7"));
        assert!(args.connector.is_none(), "the selected Konnektor");
        assert!(
            parse(&["--connector", "praxis"]).is_err(),
            "a Konnektor needs a card"
        );
        assert!(parse(&[]).is_err(), "one source is required");
        assert!(
            parse(&["--p12", "a.p12", "--card", "x"]).is_err(),
            "one source only"
        );
    }
}
