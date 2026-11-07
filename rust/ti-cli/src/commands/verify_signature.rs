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

//! `ti pki verify-signature`: an ECDSA-SHA256 signature over a file, checked against a
//! certificate's key with ti-pki's verifiers. An ePA client checks the VAU's
//! `signed_pub_keys` this way; the certificate's own standing is `pki verify`'s job.

use serde::Serialize;
use ti_client::pki::signature::{SignatureCheck, verify_signature};

use crate::cli::VerifySignatureArgs;
use crate::error::{CliError, Exit};
use crate::input;
use crate::output::{Document, Line, Output, SCHEMA, Tone};

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    #[serde(flatten)]
    check: SignatureCheck,
}

/// Runs `ti pki verify-signature`.
pub fn run(args: &VerifySignatureArgs, out: &Output) -> Result<Exit, CliError> {
    let source = input::read(&args.cert)?;
    let cert = input::certificates(&source, "00")?.remove(0).certificate;
    let data = input::read(&args.data)?;
    let signature = input::read(&args.signature)?;
    let check = verify_signature(
        &cert,
        &source.name,
        &data.bytes,
        &signature.bytes,
        &signature.name,
    )?;
    let valid = check.valid;
    let report = Report {
        schema: SCHEMA,
        check,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let check = &report.check;
        let mut doc = Document::default();
        doc.field(
            "signature",
            if valid {
                Line::status(Tone::Good, "valid")
            } else {
                Line::status(Tone::Bad, "not valid")
            }
            .and_dim(format!(
                " · {} over {} bytes, {}",
                check.hash, check.data_bytes, check.signature_format
            )),
        );
        doc.field("signer", Line::text(&check.certificate.subject));
        doc.field("key", Line::text(&check.certificate.key.algorithm));
        out.render(&doc)?;
    }
    Ok(if valid { Exit::Ok } else { Exit::Invalid })
}
