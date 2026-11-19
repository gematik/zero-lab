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

//! Writes the gRPC code of `hsm-proxy.proto`: the messages and the server into the first
//! directory given, the messages and a client without transport into the second. The sidecar
//! compiles only the first; the client serves the tests, so no client is in a production
//! build (servers.md rule 17).
//! The google protos it imports are compiled to resolve the file, but not written: no
//! message of the HSM proxy uses their types, only its HTTP annotations.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).map(PathBuf::from);
    let (Some(server), Some(client), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: ti-hsm-proxy-codegen <server directory> <client directory>");
        return ExitCode::FAILURE;
    };
    let proto = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proto");
    let mut fds = match protox::compile(
        [proto.join("gematik/zetaguard/hsmproxy/v1/hsm-proxy.proto")],
        [&proto],
    ) {
        Ok(fds) => fds,
        Err(e) => {
            eprintln!("{e:?}");
            return ExitCode::FAILURE;
        }
    };
    fds.file
        .retain(|f| f.package() == "gematik.zetaguard.hsmproxy.v1");
    for (out, server_side) in [(server, true), (client, false)] {
        let generated = tonic_prost_build::configure()
            .build_server(server_side)
            .build_client(!server_side)
            .build_transport(false)
            .emit_rerun_if_changed(false)
            .out_dir(&out)
            .compile_fds(fds.clone());
        if let Err(e) = generated {
            eprintln!("{}: {e}", out.display());
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
