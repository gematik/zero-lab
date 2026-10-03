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
