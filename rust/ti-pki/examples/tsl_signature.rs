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

//! Verifies a TSL file by its detached signature (`spec/tsl-detached`) and its signer
//! (`spec/tsl-xmldsig` part B), and prints what it found.
//!
//! ```console
//! cargo run -p ti-pki --example tsl_signature -- \
//!     ../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.xml ../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.sig
//! ```

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::Timestamp;
use ti_pki::tsl::Tsl;

fn main() -> ExitCode {
    let (Some(path), Some(sig_path)) = (std::env::args().nth(1), std::env::args().nth(2)) else {
        eprintln!("usage: tsl_signature <tsl.xml> <tsl.sig>");
        return ExitCode::from(2);
    };
    let read = |path: &str| {
        std::fs::read(path).map_err(|e| {
            eprintln!("{path}: {e}");
            ExitCode::from(2)
        })
    };
    let (xml, sig) = match (read(&path), read(&sig_path)) {
        (Ok(xml), Ok(sig)) => (xml, sig),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let now = Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    );
    match Tsl::parse_verified_auto(&xml, &sig, now) {
        Ok(verified) => {
            println!("valid at {now} ({:?})", verified.tier);
            println!("anchor        {}", verified.anchor.subject_cn());
            println!("signer        {}", verified.signer.subject_cn());
            println!("sequence      {}", verified.tsl.sequence_number);
            println!("CAs           {}", verified.tsl.intermediate_cas().len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("invalid  {e}");
            ExitCode::FAILURE
        }
    }
}
