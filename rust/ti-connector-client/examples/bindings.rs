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
