# Spike: the PKCS#11 path through SoftHSM2

TASK-389, step 1, 2026-11-19. The sidecar's way to a key is PKCS#11 alone; this spike drives it
through SoftHSM2 and records what the token did. Every statement below is an assertion of
[`tests/spike_softhsm2.rs`](../tests/spike_softhsm2.rs), run with `just hsm-spike`.

## Setup

| | |
|---|---|
| Token | SoftHSM2 2.7.0 (Homebrew), `C_GetInfo`: "Implementation of PKCS11 2.7", interface PKCS#11 3.2 |
| Host | macOS on arm64 (Apple Silicon), natively |
| Binding | `cryptoki` 0.12.1, approved 2026-11-19 |
| Token store | a fresh temporary directory per run (`SOFTHSM2_CONF`), provisioned by the suite with TEST-ONLY PINs |
| Second opinion | signatures verified with the RustCrypto verifiers ti-pki uses (`ecdsa`, `p256`, `p384`, `bp256`), digests with `sha2` |

## What worked as specified

| Area | Finding | Test |
|---|---|---|
| Mechanisms | `CKM_EC_KEY_PAIR_GEN`, `CKM_AES_KEY_GEN`, `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512`, `CKM_AES_GCM` are listed | `task_389_7_the_token_lists_the_mechanisms_the_interface_needs` |
| Signing key | made on the token with `CKA_SENSITIVE`, `CKA_EXTRACTABLE` false; reads back `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` true, `CKA_SIGN` true, `CKA_DECRYPT`, `CKA_UNWRAP`, `CKA_DERIVE` false | `task_389_4_a_signing_key_stays_on_the_token_and_only_signs` |
| Use of a signing key for encryption | refused, `CKR_KEY_FUNCTION_NOT_PERMITTED` | same |
| Key-encryption key | AES-256 made with `CKA_ENCRYPT` and `CKA_DECRYPT` only; reads back sensitive and never extractable, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_DERIVE` false; its `CKA_VALUE` is not given out; signing with it is refused, `CKR_KEY_FUNCTION_NOT_PERMITTED` | `task_389_4_a_key_encryption_key_stays_on_the_token_and_only_encrypts_and_decrypts` |
| ECDSA over a digest | `CKM_ECDSA` on P-256 (SHA-256 digest) and P-384 (SHA-384 digest) returns r and s of the field length (64, 96 bytes), which verify with another implementation | `task_389_5_a_signature_over_a_digest_verifies_with_another_implementation` |
| ECDSA over a message | `CKM_ECDSA_SHA256`, `_SHA384`, `_SHA512` on P-256 and P-384, each combination verified with another implementation | `task_389_5_a_signature_over_a_message_verifies_with_another_implementation` |
| brainpoolP256r1 | keys made and signed with, over a digest and a message; verified with `bp256`. The open question of the task ("brainpool not confirmed") is answered for this build | `task_389_5_brainpool_p256r1_is_a_curve_this_token_signs_on` |
| AES-GCM | single-part `C_Encrypt` and `C_Decrypt` with a 12-byte IV and a 128-bit tag appended to the ciphertext; with associated data, without, and for an empty plaintext | `task_389_5_aes_gcm_authenticates_the_associated_data` |
| AES-GCM refusals | another associated data, a changed tag, a changed ciphertext: `CKR_ENCRYPTED_DATA_INVALID` | same |
| Keys by label | a key asked for and not there is made as a token object; asked for again, in this or another session, it is the same key; the same label on another curve is refused, not a second key | `task_389_3_a_key_asked_for_is_made_once_and_found_again` |
| `CKA_EC_POINT` | DER-wrapped in an OCTET STRING, as PKCS#11 specifies; the adapter returns the uncompressed SEC1 point and also takes the bare point some modules return | `task_389_7_the_public_point_is_der_wrapped_and_unwrapped_for_the_caller` |
| Errors | name the operation, the key's label and the return code (`decrypt with key …: PKCS#11 EncryptedDataInvalid`), and no data | `task_389_an_error_names_the_operation_the_key_and_the_return_code` |

## What did not, or differs from other tokens

- **SoftHSM2 does not make the GCM IV.** Handed a zeroed IV buffer it encrypts under the zero IV
  and leaves the buffer as it was. HSMs in FIPS mode do the opposite and ignore or overwrite the
  IV given. The adapter therefore has `Iv::Random` (from `C_GenerateRandom`, passed in) for
  SoftHSM2 and `Iv::FromToken` for those HSMs, and refuses a result whose IV came back
  unchanged, so a ciphertext under a fixed IV is never handed out. Which one a module needs is
  configuration of the sidecar, and the conformance suite has to find it per module (TASK-389
  #5). The interface allows both, since `Encrypt` returns the IV.
- **`CKA_VALUE` of a sensitive key** is answered with `CKR_ATTRIBUTE_SENSITIVE`, which cryptoki
  0.12 reports as an absent attribute, not as an error. The suite checks that no value comes
  back, not the return code.
- **`CKA_ENCRYPT` and `CKA_WRAP` of a private EC key** are not reported by SoftHSM2. The key
  was made with neither set; that it cannot encrypt is shown by the refusal, not by the
  attribute.
- **A digest of the wrong length** is never sent: the adapter refuses it, as the interface
  requires the digest to have the curve's length. What SoftHSM2 does with one was not tried.

## Not covered by the spike

- The gRPC interface and the sidecar (decided after this spike, maintainer 2026-11-19).
- Multi-part signing and encryption (`C_SignUpdate`): single-part only, which every operation
  of the interface needs; some HSMs do raw `CKM_ECDSA` single-part only.
- Linux and x86_64: run only on macOS arm64 so far.
- Deterministic keys for tests that compare output (TASK-389 #3): SoftHSM2 makes keys from its
  own random source; output is comparable only through a given IV, not a given key.
- Kryoptic, NSS softokn and every vendor's module.
