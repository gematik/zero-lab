//! Verifies the signature of a TSL file (`spec/tsl-xmldsig`, part A): the XMLDSig/XAdES
//! profile, the reference digests and the ECDSA value under the signer certificate's key.
//! The signer is not yet checked against the TSL signer CA.
//!
//! ```console
//! cargo run -p ti-pki --example tsl_signature -- ../spec/tsl-xmldsig/testdata/tsl/real/pu-10334.xml
//! ```

use std::process::ExitCode;

use ti_pki::algorithms::DEFAULT;
use ti_pki::tsl_signature;

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
    match tsl_signature::verify(&xml, DEFAULT) {
        Ok(signed) => {
            println!("signature valid (TSLSIG-001, 010 – 023)");
            println!("signer        {}", signed.signer.subject_cn());
            println!("issuer        {}", signed.signer.issuer_cn());
            println!("signing time  {}", signed.signing_time);
            println!("content       {} bytes", signed.content.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!(
                "invalid  {} ({})  {}: {}",
                e.code,
                e.code.number(),
                e.rule,
                e.detail
            );
            ExitCode::FAILURE
        }
    }
}
