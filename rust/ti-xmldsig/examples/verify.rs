//! Checks the signature of a TSL file against the profile of `spec/tsl-xmldsig` and, as a
//! caller would, verifies the ECDSA value with the signer certificate's key.
//!
//! ```console
//! cargo run -p ti-xmldsig --example verify -- ../spec/tsl-xmldsig/testdata/tsl/real/pu-10334.xml
//! ```

use std::process::ExitCode;

use bp256::BrainpoolP256r1;
use ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
use ti_xmldsig::{Document, Limits};
use x509_cert::Certificate;
use x509_cert::der::Decode;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: verify <tsl.xml>");
        return ExitCode::from(2);
    };
    let xml = match std::fs::read(&path) {
        Ok(xml) => xml,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::from(2);
        }
    };
    let signed = match Document::parse(&xml, &Limits::TSL).and_then(|d| d.verify_tsl_signature()) {
        Ok(signed) => signed,
        Err(e) => {
            println!("invalid  {:?}  {e}", e.kind());
            return ExitCode::FAILURE;
        }
    };
    println!("profile and digests ok (TSLSIG-010 – 017, 019 – 023)");
    println!("signing time        {}", signed.signing_time);
    println!("signer serial       {}", signed.signer_serial);
    println!(
        "signer cert SHA-256 {}",
        hex(&Sha256::digest(&signed.signer_certificate))
    );
    println!("signed info         {} bytes", signed.signed_info.len());
    println!(
        "content             {} bytes, SHA-256 {}",
        signed.content.len(),
        hex(&Sha256::digest(&signed.content))
    );

    // The caller's part, which ti-pki does with its own algorithms and the signer's chain.
    let certificate = match Certificate::from_der(&signed.signer_certificate) {
        Ok(c) => c,
        Err(e) => {
            println!("invalid  signer certificate: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "signer              {}",
        certificate.tbs_certificate().subject()
    );
    let serial = certificate.tbs_certificate().serial_number().as_bytes();
    let significant =
        |bytes: &[u8]| -> Vec<u8> { bytes.iter().copied().skip_while(|b| *b == 0).collect() };
    let serial_matches = signed
        .signer_serial
        .parse::<u128>()
        .is_ok_and(|s| significant(&s.to_be_bytes()) == significant(serial));
    let key = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let verified = ecdsa::VerifyingKey::<BrainpoolP256r1>::from_sec1_bytes(key)
        .ok()
        .zip(ecdsa::Signature::<BrainpoolP256r1>::from_slice(&signed.signature).ok())
        .is_some_and(|(key, signature)| key.verify(&signed.signed_info, &signature).is_ok());
    println!(
        "serial matches cert {}",
        if serial_matches { "yes" } else { "NO" }
    );
    println!(
        "ECDSA bp256r1       {}",
        if verified { "valid" } else { "INVALID" }
    );
    if serial_matches && verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
