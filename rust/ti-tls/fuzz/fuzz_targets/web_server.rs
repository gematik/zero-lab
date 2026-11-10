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

//! Any bytes as the chain a server presents, up to four certificates each behind a two-byte
//! big-endian length, under the web profile with the corpus's root and no revocation source: the check never
//! panics, and whatever comes out valid carries `revocation_unavailable`, rests on no status and is not
//! reused (TLSV-044, TLSV-050). The seed is the corpus's valid chain.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls_pki_types::CertificateDer;
use ti_pki::Timestamp;
use ti_tls::{Offline, WebCheck};

const ROOT: &[u8] = include_bytes!("../../../../spec/pki-validation/testdata/web-root.pem");

fuzz_target!(|data: &[u8]| {
    let root = ti_pki::parse_pem_certificates(ROOT).unwrap().remove(0);
    let check = WebCheck::new([CertificateDer::from(root.der().to_vec())]);
    let mut chain = Vec::new();
    let mut rest = data;
    while chain.len() < 4
        && let [high, low, tail @ ..] = rest
    {
        let len = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        chain.push(CertificateDer::from(tail[..len].to_vec()));
        rest = &tail[len..];
    }
    let verdict = futures_lite::future::block_on(check.verify(
        &chain,
        "www.web.test",
        None,
        Timestamp(1_767_225_600),
        &Offline,
    ));
    // Offline: no revocation source answers, so nothing valid rests on a status.
    if verdict.is_valid() {
        assert!(
            verdict.warnings.contains(&ti_tls::verdict::REVOCATION_UNAVAILABLE)
                && verdict.status_source.is_none()
                && verdict.reusable_until.is_none(),
            "{verdict:?}"
        );
    }
});
