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

//! Verifies a TSL file (`spec/tsl-xmldsig`, parts A and B): the XMLDSig/XAdES profile,
//! the reference digests, the ECDSA value and a C.TSL.SIG signer issued by the embedded
//! TSL signer CA of whichever environment it belongs to, at the current time.
//!
//! ```console
//! cargo run -p ti-pki --example tsl_signature -- ../spec/tsl-xmldsig/testdata/tsl/real/pu-10334.xml
//! ```

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ti_pki::Timestamp;
use ti_pki::tsl::Tsl;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: tsl_signature <tsl.xml>");
        return ExitCode::from(2);
    };
    let xml = match std::fs::read(&path) {
        Ok(xml) => xml,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    let now = Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    );
    match Tsl::parse_verified_auto(&xml, now) {
        Ok(verified) => {
            println!("valid at {now} ({:?})", verified.tier);
            println!("anchor        {}", verified.anchor.subject_cn());
            println!("signer        {}", verified.signer.subject_cn());
            println!("signing time  {}", verified.signing_time);
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
