"""OpenSSL command-line adapter of the PKCS#12 conformance harness.

    python3 decoder.py decode --password-file FILE P12

Runs `openssl pkcs12 -legacy -nodes` and reads the PEM output. OpenSSL's exit
status tells success from failure only, so the harness runs it with -coarse.
Keys are re-encoded by OpenSSL and match by their public key.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys

OPENSSL = os.environ.get("OPENSSL", "openssl")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args, stdin=None):
    return subprocess.run([OPENSSL, *args], input=stdin, capture_output=True, check=False)


def text(raw: bytes) -> str:
    # OpenSSL prints friendly names as UTF-8 when it can and as Latin-1 when not.
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def decode(path: str, password_file: str) -> dict:
    result = {"code": "ok", "certificates": [], "keys": [], "pairs": [], "mac": None}
    # An empty file:... password reads as no password; pass: gives the empty one.
    passin = "file:" + password_file if os.path.getsize(password_file) else "pass:"
    out = run(["pkcs12", "-in", path, "-passin", passin, "-nodes", "-legacy"])
    if out.returncode != 0:
        return {**result, "code": "error", "detail": out.stderr.decode(errors="replace").strip()[:300]}

    cert_ids, key_ids = [], []
    for block in re.split(r"(?=Bag Attributes)", text(out.stdout)):
        name = re.search(r"friendlyName: (.*)", block)
        local_id = re.search(r"localKeyID: ([0-9A-F ]+)", block)
        pem = re.search(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", block, re.S)
        if not pem:
            continue
        der = base64.b64decode("".join(pem.group(2).split()))
        item = {}
        if name:
            item["friendly_name"] = name.group(1).strip()
        if pem.group(1) == "CERTIFICATE":
            item["sha256"] = sha256(der)
            result["certificates"].append(item)
            cert_ids.append(local_id.group(1).strip() if local_id else None)
        elif "PRIVATE KEY" in pem.group(1):
            spki = run(["pkey", "-inform", "DER", "-pubout", "-outform", "DER"], stdin=der)
            if spki.returncode == 0:
                item["public_key_sha256"] = sha256(spki.stdout)
            result["keys"].append(item)
            key_ids.append(local_id.group(1).strip() if local_id else None)
    for ci, cid in enumerate(cert_ids):
        if cid and cid in key_ids:
            result["pairs"].append([ci, key_ids.index(cid)])

    info = run(["pkcs12", "-in", path, "-passin", passin, "-info", "-noout", "-legacy"])
    mac = re.search(r"MAC: (\S+),", info.stderr.decode(errors="replace"))
    if mac:
        result["mac"] = mac.group(1).lower()
    return result


def main() -> None:
    if len(sys.argv) != 5 or sys.argv[1:3] != ["decode", "--password-file"]:
        sys.exit("usage: decoder.py decode --password-file FILE P12")
    print(json.dumps(decode(sys.argv[4], sys.argv[3])))


if __name__ == "__main__":
    main()
