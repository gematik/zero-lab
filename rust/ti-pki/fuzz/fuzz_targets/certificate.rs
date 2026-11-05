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

//! Any bytes as a DER certificate, as a peer, a bundle or a TSL hands one over before any signature
//! is checked: decoding errors or yields a certificate that decodes from its own DER to the same
//! value, and every accessor path validation and the type detection read answers without panicking.
//! The same bytes as PEM go through the PEM reader. The seeds are the test PKI's certificates and the
//! embedded anchors.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_pki::{Certificate, detect_certificate_type, parse_pem_certificates};

fuzz_target!(|data: &[u8]| {
    if let Ok(cert) = Certificate::from_der(data) {
        let again = Certificate::from_der(cert.der()).expect("a certificate's own DER decodes");
        assert!(again == cert, "decoding the DER again changed the certificate");
        let _ = (cert.subject_cn(), cert.issuer_cn(), cert.not_after(), cert.is_ca());
        let _ = (cert.serial(), cert.public_key(), cert.admission());
        let _ = detect_certificate_type(&cert);
    }
    let _ = parse_pem_certificates(data);
});
