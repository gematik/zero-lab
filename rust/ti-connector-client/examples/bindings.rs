//! Which service versions and endpoints a Konnektor call would use, from a `.kon` file
//! and a captured `connector.sds`; no network.
//!
//! `cargo run -p ti-connector-client --example bindings -- praxis.kon connector.sds`

use std::process::ExitCode;

use ti_connector_client::{BINDINGS, Dotkon, ServiceDirectory};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [kon, sds] = args.as_slice() else {
        eprintln!("usage: bindings KON_PATH SDS_PATH");
        return ExitCode::from(2);
    };
    match run(kon, sds) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(kon: &str, sds: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dotkon = Dotkon::parse(&std::fs::read(kon)?)?;
    let mut directory = ServiceDirectory::parse(&std::fs::read(sds)?)?;
    if dotkon.rewrite_service_endpoints {
        directory.rewrite_endpoints(&dotkon.url);
    }
    let p = &directory.product;
    println!(
        "{} {} {} (FW {}) at {}",
        p.vendor_id, p.product_type, p.product_type_version, p.fw_version, dotkon.url
    );
    if !dotkon.variables.is_empty() {
        println!("expanded: {}", dotkon.variables.join(", "));
    }
    for (service, versions) in BINDINGS {
        for version in *versions {
            match directory.resolve(service, &[version]) {
                Ok(b) => println!(
                    "{service:<22} {version:<4} → {:<7} {}",
                    b.version, b.endpoint
                ),
                Err(e) => println!("{service:<22} {version:<4} → {e}"),
            }
        }
    }
    Ok(())
}
