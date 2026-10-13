"""pyca/cryptography adapter of the PKCS#12 conformance harness.

    python3 decoder.py decode --password-file FILE P12

Writes the JSON of spec/pkcs12/CONFORMANCE.md (command-line contract). The
library reports no reason for a failure, so the harness runs it with -coarse.
Keys are re-encoded by the library and match by their public key.
"""

import hashlib
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode(data: bytes, password: bytes) -> dict:
    result = {"code": "ok", "certificates": [], "keys": [], "pairs": [], "mac": None}
    try:
        p12 = pkcs12.load_pkcs12(data, password)
    except Exception as e:  # noqa: BLE001 - the library raises ValueError and others alike
        return {**result, "code": "error", "detail": str(e)}

    certs = ([p12.cert] if p12.cert else []) + list(p12.additional_certs)
    for c in certs:
        item = {"sha256": sha256(c.certificate.public_bytes(serialization.Encoding.DER))}
        if c.friendly_name:
            item["friendly_name"] = c.friendly_name.decode("utf-8")
        result["certificates"].append(item)
    if p12.key is not None:
        spki = p12.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        result["keys"].append({"public_key_sha256": sha256(spki)})
        if p12.cert is not None:
            result["pairs"].append([0, 0])
    return result


def main() -> None:
    if len(sys.argv) != 5 or sys.argv[1:3] != ["decode", "--password-file"]:
        sys.exit("usage: decoder.py decode --password-file FILE P12")
    with open(sys.argv[3], "rb") as f:
        password = f.read()
    with open(sys.argv[4], "rb") as f:
        data = f.read()
    print(json.dumps(decode(data, password)))


if __name__ == "__main__":
    main()
