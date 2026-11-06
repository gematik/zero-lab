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

//! Signature algorithms: ti-pki's, so brainpool and RSA verify the same way in certificates
//! and in the handshake, with no second crypto library.

use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls_pki_types::SignatureVerificationAlgorithm;
use ti_pki::algorithms::{self, brainpool, rsa};

/// TLS 1.3's `ecdsa_brainpoolP256r1tls13_sha256` and its P384 sibling (RFC 8734), which
/// rustls does not know by name.
pub const BRAINPOOL_P256_TLS13: u16 = 0x081a;
/// See [`BRAINPOOL_P256_TLS13`].
pub const BRAINPOOL_P384_TLS13: u16 = 0x081b;

/// Handshake signatures under the `ti` profile (TLSV-013): TLS 1.2's ECDSA schemes name a
/// hash, not a curve, so the brainpool variant of each is a candidate too.
pub static TI_SCHEMES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        algorithms::ECDSA_P256_SHA256,
        algorithms::ECDSA_P384_SHA384,
        brainpool::ECDSA_BP256R1_SHA256,
        brainpool::ECDSA_BP384R1_SHA384,
        rsa::RSA_PSS_SHA256,
        rsa::RSA_PSS_SHA384,
        rsa::RSA_PSS_SHA512,
        rsa::RSA_PKCS1_SHA256,
        rsa::RSA_PKCS1_SHA384,
        rsa::RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                algorithms::ECDSA_P256_SHA256,
                brainpool::ECDSA_BP256R1_SHA256,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                algorithms::ECDSA_P384_SHA384,
                brainpool::ECDSA_BP384R1_SHA384,
            ],
        ),
        (SignatureScheme::RSA_PSS_SHA256, &[rsa::RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[rsa::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[rsa::RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[rsa::RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[rsa::RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[rsa::RSA_PKCS1_SHA512]),
    ],
};

/// Handshake signatures under the `web` profile (TLSV-013): no brainpool.
pub static WEB_SCHEMES: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: WEB_CERTIFICATE_ALGORITHMS,
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[algorithms::ECDSA_P256_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[algorithms::ECDSA_P384_SHA384],
        ),
        (SignatureScheme::RSA_PSS_SHA256, &[rsa::RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[rsa::RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[rsa::RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[rsa::RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[rsa::RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[rsa::RSA_PKCS1_SHA512]),
    ],
};

/// The certificate signatures a `web` path may carry (TLSV-023): SHA-256 and up; SHA-1,
/// MD5 and SHA-224 are not among them, so a path with one does not build.
pub static WEB_CERTIFICATE_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[
    algorithms::ECDSA_P256_SHA256,
    algorithms::ECDSA_P384_SHA384,
    rsa::RSA_PSS_SHA256,
    rsa::RSA_PSS_SHA384,
    rsa::RSA_PSS_SHA512,
    rsa::RSA_PKCS1_SHA256,
    rsa::RSA_PKCS1_SHA384,
    rsa::RSA_PKCS1_SHA512,
];
