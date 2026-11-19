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

//! Writes the gRPC code of `hsm-proxy.proto` into the directory given as the one argument.
//! The server and a client without transport are generated; the client serves the tests.
//! The google protos it imports are compiled to resolve the file, but not written: no
//! message of the HSM proxy uses their types, only its HTTP annotations.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(out) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: ti-hsm-proxy-codegen <output directory>");
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
    let generated = tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .build_transport(false)
        .emit_rerun_if_changed(false)
        .out_dir(&out)
        .compile_fds(fds);
    match generated {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
