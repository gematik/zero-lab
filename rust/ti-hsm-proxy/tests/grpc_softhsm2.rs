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

//! The gRPC interface of the HSM proxy (gemSpec_ZETA A_28829) end to end: a client of the
//! generated code, over the Unix socket, against the sidecar on a software token.
//!
//! Gated like the spike suite: `just hsm-spike` sets `TI_HSM_PKCS11_MODULE_PATH` and a fresh
//! `SOFTHSM2_CONF`. The token is provisioned with TEST-ONLY PINs and the keys are made on it.

#![cfg(feature = "grpc")]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64ct::Encoding as _;
use cryptoki::types::AuthPin;
use ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::Digest as _;
use ti_hsm_proxy::grpc::proto::health_check_response::ServingStatus;
use ti_hsm_proxy::grpc::proto::hsm_proxy_service_client::HsmProxyServiceClient;
use ti_hsm_proxy::grpc::proto::{
    DecryptRequest, DigestAlgorithm, EncryptRequest, GetCertificateRequest, GetPublicKeyRequest,
    HealthCheckRequest, SignRequest, SymmetricEncryptionAlgorithm,
};
use ti_hsm_proxy::{HsmProxy, Iv, KeyKind, KeySpec, MissingKeys, Module};
use tonic::Code;
use tonic::transport::Channel;

const TOKEN: &str = "ti-hsm-proxy-grpc";

/// A runtime, the sidecar on its socket in it, a channel to that socket, and the socket's
/// path; started once.
fn started() -> &'static (tokio::runtime::Runtime, Channel, PathBuf) {
    static STARTED: OnceLock<(tokio::runtime::Runtime, Channel, PathBuf)> = OnceLock::new();
    STARTED.get_or_init(|| {
        let path = std::env::var_os("TI_HSM_PKCS11_MODULE_PATH")
            .map(PathBuf::from)
            .expect("TI_HSM_PKCS11_MODULE_PATH: the PKCS#11 module to drive (just hsm-spike)");
        let pin = AuthPin::from("user-pin-TEST-ONLY");
        let module = Module::load(&path).expect("the module loads");
        module
            .provision(TOKEN, &AuthPin::from("so-pin-TEST-ONLY"), &pin)
            .expect("the token is provisioned");
        let pool = module
            .pool(TOKEN, &pin, std::num::NonZeroUsize::new(4).unwrap())
            .expect("a pool");
        let keys = [
            ("sig-p256", KeyKind::EcdsaP256),
            ("sig-p384", KeyKind::EcdsaP384),
            ("kek-v1", KeyKind::Aes256Gcm),
        ]
        .map(|(key_id, kind)| KeySpec {
            key_id: key_id.to_owned(),
            kind,
        });
        let proxy = HsmProxy::start(
            pool,
            &keys,
            MissingKeys::Make,
            Duration::from_secs(5),
            Iv::Random,
            module.describe().unwrap(),
        )
        .expect("the keys are on the token");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let socket = std::env::temp_dir().join(format!("ti-hsm-proxy-{}.sock", std::process::id()));
        let serving = socket.clone();
        let probed = socket.clone();
        runtime.spawn(async move {
            ti_hsm_proxy::grpc::serve(
                Arc::new(proxy),
                &serving,
                Duration::from_millis(200),
                std::future::pending(),
            )
            .await
            .expect("the server runs");
        });
        let channel = runtime.block_on(async move {
            for _ in 0..100 {
                if socket.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            ti_hsm_proxy::grpc::connect(&socket)
                .await
                .expect("a channel to the socket")
        });
        (runtime, channel, probed)
    })
}

fn client() -> (
    &'static tokio::runtime::Runtime,
    HsmProxyServiceClient<Channel>,
) {
    let (runtime, channel, _) = started();
    (runtime, HsmProxyServiceClient::new(channel.clone()))
}

fn code<T: std::fmt::Debug>(result: Result<T, tonic::Status>) -> Code {
    result.expect_err("the sidecar refused").code()
}

fn point(
    runtime: &tokio::runtime::Runtime,
    client: &mut HsmProxyServiceClient<Channel>,
    key_id: &str,
) -> Vec<u8> {
    let key = runtime
        .block_on(client.get_public_key(GetPublicKeyRequest {
            key_id: key_id.to_owned(),
        }))
        .unwrap()
        .into_inner();
    // SubjectPublicKeyInfo ends with the uncompressed point in its BIT STRING.
    let len = if key_id == "sig-p256" { 65 } else { 97 };
    key.public_key_der[key.public_key_der.len() - len..].to_vec()
}

/// A_28829 Sign: a signature over a digest (NONE) and over data the token hashes, r and s
/// of the curve's length (IEEE P1363), verifies with another implementation against the
/// key GetPublicKey returns.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn a_28829_sign_returns_r_and_s_that_verify_against_get_public_key() {
    let (runtime, mut client) = client();
    let p256 = point(runtime, &mut client, "sig-p256");
    let p384 = point(runtime, &mut client, "sig-p384");
    let message = b"signed through the HSM proxy";
    for (key_id, algorithm, data, digest) in [
        (
            "sig-p256",
            DigestAlgorithm::None,
            sha2::Sha256::digest(message).to_vec(),
            sha2::Sha256::digest(message).to_vec(),
        ),
        (
            "sig-p256",
            DigestAlgorithm::Sha256,
            message.to_vec(),
            sha2::Sha256::digest(message).to_vec(),
        ),
        (
            "sig-p384",
            DigestAlgorithm::None,
            sha2::Sha384::digest(message).to_vec(),
            sha2::Sha384::digest(message).to_vec(),
        ),
        (
            "sig-p384",
            DigestAlgorithm::Sha384,
            message.to_vec(),
            sha2::Sha384::digest(message).to_vec(),
        ),
    ] {
        let response = runtime
            .block_on(client.sign(SignRequest {
                key_id: key_id.to_owned(),
                data,
                algorithm: algorithm.into(),
            }))
            .unwrap()
            .into_inner();
        assert_eq!(response.key_id, key_id);
        let verified = if key_id == "sig-p256" {
            let key = ecdsa::VerifyingKey::<p256::NistP256>::from_sec1_bytes(&p256).unwrap();
            let signature =
                ecdsa::Signature::<p256::NistP256>::from_slice(&response.signature).unwrap();
            key.verify_prehash(&digest, &signature).is_ok()
        } else {
            let key = ecdsa::VerifyingKey::<p384::NistP384>::from_sec1_bytes(&p384).unwrap();
            let signature =
                ecdsa::Signature::<p384::NistP384>::from_slice(&response.signature).unwrap();
            key.verify_prehash(&digest, &signature).is_ok()
        };
        assert!(verified, "{key_id} {algorithm:?}");
    }
}

/// A_28829 GetPublicKey: the same key as PEM, DER and JWK, and the JWK names its curve.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn a_28829_get_public_key_returns_pem_der_and_jwk_of_one_key() {
    let (runtime, mut client) = client();
    let key = runtime
        .block_on(client.get_public_key(GetPublicKeyRequest {
            key_id: "sig-p384".to_owned(),
        }))
        .unwrap()
        .into_inner();
    let (label, der) = pem_rfc7468::decode_vec(key.public_key_pem.as_bytes()).unwrap();
    assert_eq!(label, "PUBLIC KEY");
    assert_eq!(der, key.public_key_der);
    // SEQUENCE { SEQUENCE { id-ecPublicKey, secp384r1 }, BIT STRING { 0x04 x y } }
    let header = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
    ];
    let (prefix, point) = key.public_key_der.split_at(header.len());
    assert_eq!(prefix, header);
    assert!(p384::PublicKey::from_sec1_bytes(point).is_ok());
    let jwk: serde_json::Value = serde_json::from_str(&key.jwk_json).unwrap();
    let coordinate =
        |name: &str| base64ct::Base64UrlUnpadded::decode_vec(jwk[name].as_str().unwrap()).unwrap();
    assert_eq!(jwk["kty"], "EC");
    assert_eq!([coordinate("x"), coordinate("y")].concat(), point[1..]);
    assert!(
        key.jwk_json.contains(r#""crv":"P-384""#),
        "{}",
        key.jwk_json
    );
}

/// A_28829 Encrypt and Decrypt: AES-256-GCM with associated data, the IV and tag returned
/// apart; another associated data, a changed tag or a changed ciphertext is refused with
/// INVALID_ARGUMENT, and nothing of the plaintext comes back.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn a_28829_encrypt_and_decrypt_authenticate_the_associated_data() {
    let (runtime, mut client) = client();
    let sealed = runtime
        .block_on(client.encrypt(EncryptRequest {
            key_id: "kek-v1".to_owned(),
            plaintext: b"a data-encryption key, 32 bytes!".to_vec(),
            algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            associated_data: b"row 17".to_vec(),
        }))
        .unwrap()
        .into_inner();
    assert_eq!(
        (sealed.iv.len(), sealed.tag.len(), sealed.ciphertext.len()),
        (12, 16, 32)
    );
    let decrypt = |aad: &[u8], tag: &[u8], ciphertext: &[u8]| DecryptRequest {
        key_id: "kek-v1".to_owned(),
        ciphertext: ciphertext.to_vec(),
        algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
        iv: sealed.iv.clone(),
        tag: tag.to_vec(),
        associated_data: aad.to_vec(),
    };
    let plaintext = runtime
        .block_on(client.decrypt(decrypt(b"row 17", &sealed.tag, &sealed.ciphertext)))
        .unwrap()
        .into_inner()
        .plaintext;
    assert_eq!(plaintext, b"a data-encryption key, 32 bytes!");
    let mut tag = sealed.tag.clone();
    tag[0] ^= 1;
    let mut ciphertext = sealed.ciphertext.clone();
    ciphertext[0] ^= 1;
    for request in [
        decrypt(b"row 18", &sealed.tag, &sealed.ciphertext),
        decrypt(b"row 17", &tag, &sealed.ciphertext),
        decrypt(b"row 17", &sealed.tag, &ciphertext),
    ] {
        assert_eq!(
            code(runtime.block_on(client.decrypt(request))),
            Code::InvalidArgument
        );
    }
}

/// A_28820: what does not fit the operation is refused before the token sees it: an
/// unknown key, a key of the other use, a digest of another length than the curve's, an
/// algorithm left UNSPECIFIED or one the proto does not define.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn a_28820_requests_that_do_not_fit_the_operation_are_refused() {
    let (runtime, mut client) = client();
    let sign = |key_id: &str, data: Vec<u8>, algorithm: i32| SignRequest {
        key_id: key_id.to_owned(),
        data,
        algorithm,
    };
    for (request, expected) in [
        (sign("no-such-key", vec![0; 32], 0), Code::NotFound),
        (sign("kek-v1", vec![0; 32], 0), Code::FailedPrecondition),
        (sign("sig-p256", vec![0; 48], 0), Code::InvalidArgument),
        (sign("sig-p256", vec![0; 32], 99), Code::InvalidArgument),
        (
            sign("bad label with spaces", vec![0; 32], 0),
            Code::NotFound,
        ),
    ] {
        assert_eq!(code(runtime.block_on(client.sign(request))), expected);
    }
    for (key_id, algorithm, expected) in [
        (
            "kek-v1",
            SymmetricEncryptionAlgorithm::SymmetricEncryptionUnspecified.into(),
            Code::InvalidArgument,
        ),
        ("kek-v1", 7, Code::InvalidArgument),
        (
            "sig-p256",
            SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
            Code::FailedPrecondition,
        ),
    ] {
        let request = EncryptRequest {
            key_id: key_id.to_owned(),
            plaintext: vec![1; 32],
            algorithm,
            associated_data: Vec::new(),
        };
        assert_eq!(code(runtime.block_on(client.encrypt(request))), expected);
    }
    let too_large = EncryptRequest {
        key_id: "kek-v1".to_owned(),
        plaintext: vec![1; ti_hsm_proxy::MAX_DATA_LEN + 1],
        algorithm: SymmetricEncryptionAlgorithm::Aes256Gcm.into(),
        associated_data: Vec::new(),
    };
    assert_eq!(
        code(runtime.block_on(client.encrypt(too_large))),
        Code::InvalidArgument
    );
}

/// A_28829 GetCertificate: a key without a certificate on the token is NOT_FOUND, never an
/// empty answer.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn a_28829_get_certificate_of_a_key_without_one_is_not_found() {
    let (runtime, mut client) = client();
    let request = GetCertificateRequest {
        key_id: "sig-p256".to_owned(),
    };
    assert_eq!(
        code(runtime.block_on(client.get_certificate(request))),
        Code::NotFound
    );
}

/// A_28829 HealthCheck: SERVING while a session reaches the token, with the version and
/// the module's description.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn a_28829_health_check_reports_the_token_and_the_version() {
    let (runtime, mut client) = client();
    let health = runtime
        .block_on(client.health_check(HealthCheckRequest {}))
        .unwrap()
        .into_inner();
    assert_eq!(health.status, i32::from(ServingStatus::Serving));
    assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
    assert!(health.hsm_info.contains("PKCS#11"), "{}", health.hsm_info);
}

/// TASK-389: the sidecar's health can be measured from outside. `grpc.health.v1` reports
/// SERVING overall and for HsmProxyService once the token answered, and the probe that
/// `hsm-proxy health` runs for an exec probe reads it over the socket.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_the_sidecars_health_is_probed_over_its_socket() {
    use tonic_health::pb::health_check_response::ServingStatus as Status;
    use tonic_health::pb::health_client::HealthClient;

    let (runtime, channel, socket) = started();
    assert!(runtime.block_on(ti_hsm_proxy::grpc::probe(socket)).unwrap());
    let mut health = HealthClient::new(channel.clone());
    for service in ["", ti_hsm_proxy::grpc::SERVICE_NAME] {
        let status = runtime
            .block_on(health.check(tonic_health::pb::HealthCheckRequest {
                service: service.to_owned(),
            }))
            .unwrap()
            .into_inner()
            .status;
        assert_eq!(status, i32::from(Status::Serving), "{service:?}");
    }
    let absent = std::env::temp_dir().join("ti-hsm-proxy-no-such.sock");
    assert!(
        runtime
            .block_on(ti_hsm_proxy::grpc::probe(&absent))
            .is_err()
    );
}
