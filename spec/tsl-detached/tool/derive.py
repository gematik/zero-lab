#!/usr/bin/env python3
# Copyright (Change Date see Readme), gematik GmbH
#
# Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
# European Commission – subsequent versions of the EUPL (the "Licence").
# You may not use this work except in compliance with the Licence.
#
# You find a copy of the Licence in the "Licence" file or at
# https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the Licence is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
# In case of changes by gematik find details in the "Readme" file.
#
# See the Licence for the specific language governing permissions and limitations under the Licence.
"""Derives the negative fixtures of spec/tsl-detached from the captured sets.

    python3 -I tool/derive.py testdata

Standard library only. Every output is a deterministic function of the captured
files, so the derived fixtures are committed and this tool documents them.
"""

import json
import pathlib
import shutil
import sys

ECDSA_WITH_SHA256 = bytes.fromhex("06082a8648ce3d040302")
ECDSA_WITH_SHA384 = bytes.fromhex("06082a8648ce3d040303")


def tlv(data, at):
    """The tag, the value and the offset after a DER TLV at `at`."""
    tag = data[at]
    length = data[at + 1]
    at += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[at : at + n], "big")
        at += n
    return tag, data[at : at + length], at + length


def der_length(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der(tag, value):
    return bytes([tag]) + der_length(len(value)) + value


def parts(sig):
    """The three elements of a .sig file, as raw TLVs."""
    tag, body, end = tlv(sig, 0)
    assert tag == 0x30 and end == len(sig), "not one SEQUENCE"
    elements = []
    at = 0
    while at < len(body):
        tag, _, nxt = tlv(body, at)
        elements.append(body[at:nxt])
        at = nxt
    assert len(elements) == 3, "the SEQUENCE has not three elements"
    return elements


def rebuild(alg, bits, cert):
    return der(0x30, alg + bits + cert)


def plain_signature(bits_tlv):
    """The BIT STRING with the DER ECDSA-Sig-Value replaced by r ‖ s (32 bytes each)."""
    _, bits, _ = tlv(bits_tlv, 0)
    assert bits[0] == 0, "unused bits"
    _, rs, _ = tlv(bits[1:], 0)
    _, r, after_r = tlv(rs, 0)
    _, s, _ = tlv(rs, after_r)
    plain = r[-32:].rjust(32, b"\0") + s[-32:].rjust(32, b"\0")
    return der(0x03, b"\0" + plain)


def main(testdata):
    testdata = pathlib.Path(testdata)
    ref = testdata / "ref"
    derived = testdata / "derived"
    derived.mkdir(exist_ok=True)
    ref_sig = (ref / "ECC-RSA_TSL-ref.sig").read_bytes()
    ref_xml = (ref / "ECC-RSA_TSL-ref.xml").read_bytes()
    prod_sig = (testdata / "prod" / "ECC-RSA_TSL.sig").read_bytes()
    alg, bits, cert = parts(ref_sig)

    outputs = {
        "prod-sig-on-ref-xml.sig": prod_sig,
        "ref-truncated.sig": ref_sig[:700],
        "ref-trailing-byte.sig": ref_sig + b"\0",
        "ref-flipped-signature-byte.sig": rebuild(
            alg, bits[:-1] + bytes([bits[-1] ^ 0x01]), cert
        ),
        "ref-wrong-algorithm.sig": rebuild(
            alg.replace(ECDSA_WITH_SHA256, ECDSA_WITH_SHA384), bits, cert
        ),
        "ref-plain-signature.sig": rebuild(alg, plain_signature(bits), cert),
        "ref-unused-bits.sig": rebuild(alg, bits[:2] + b"\x01" + bits[3:], cert),
        "ref-tampered.xml": ref_xml[:1000] + bytes([ref_xml[1000] ^ 0x01]) + ref_xml[1001:],
    }
    assert ECDSA_WITH_SHA256 in alg, "the ref signature is not ecdsa-with-SHA256"
    for name, data in outputs.items():
        (derived / name).write_bytes(data)
    stale = pathlib.Path(__file__).resolve().parents[3] / (
        "rust/ti-pki/tests/fixtures/ocsp-tsl-signing-unit-12-test-only.der"
    )
    shutil.copyfile(stale, derived / "stale.ocsp")

    entries = [
        ("ref-truncated.sig", "TSLDET-001", "detached_signature_error"),
        ("ref-trailing-byte.sig", "TSLDET-001", "detached_signature_error"),
        ("ref-wrong-algorithm.sig", "TSLDET-002", "detached_signature_error"),
        ("ref-plain-signature.sig", "TSLDET-003", "detached_signature_error"),
        ("ref-unused-bits.sig", "TSLDET-003", "detached_signature_error"),
        ("ref-flipped-signature-byte.sig", "TSLDET-005", "detached_signature_error"),
        ("prod-sig-on-ref-xml.sig", "TSLDET-005", "detached_signature_error"),
    ]
    for name, rule, code in entries:
        print(
            json.dumps(
                {
                    "path": "ref/ECC-RSA_TSL-ref.xml",
                    "signature": f"derived/{name}",
                    "producer": "derive.py",
                    "rules": [rule],
                    "env": "nonprod",
                    "expect": {"result": "invalid", "code": code, "rule": rule},
                }
            )
        )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "testdata")
