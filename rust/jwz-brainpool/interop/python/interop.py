"""Python oracle of jwz-brainpool's interop fixtures, on jwcrypto.

    python interop.py gen   <keys.json> <out.json>             tokens jwcrypto makes, for jwz
    python interop.py check <keys.json> <jwz.json> <out.json>  jwcrypto's verdicts on jwz's tokens

jwcrypto binds ES256 to P-256, so it skips ePA's ES256 on brainpool keys. Brainpool JWE
goes one way only: jwz encrypts, jwcrypto decrypts (jwz does not decrypt it yet).
"""

import hashlib
import json
import platform
import sys
from importlib.metadata import version

from jwcrypto import jwe, jwk, jws

LIBRARY = (
    f"jwcrypto {version('jwcrypto')} (Python {platform.python_version()}, "
    f"cryptography {version('cryptography')})"
)
SIGNATURE_ALGS = ["BP256R1"]


def payload(case_id):
    return json.dumps({"case": case_id, "iss": "jwz-interop"}, separators=(",", ":"), sort_keys=True)


def read_keys(path):
    with open(path) as f:
        return {name: jwk.JWK(**value) for name, value in json.load(f).items()}


def write_json(path, value):
    with open(path, "w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def sign(case_id, keys, serialization):
    token = jws.JWS(payload(case_id).encode())
    token.allowed_algs = SIGNATURE_ALGS
    for name in keys:
        protected = {"alg": "BP256R1", "kid": name}
        if serialization == "compact":
            protected["typ"] = "JWT"
        token.add_signature(KEYS[name], alg="BP256R1", protected=json.dumps(protected))
    text = token.serialize(compact=serialization == "compact")
    return {
        "id": case_id,
        "kind": "jws",
        "serialization": serialization,
        "algs": ["BP256R1"] * len(keys),
        "keys": keys,
        "payload": payload(case_id),
        "token": text,
    }


def gen(out_path):
    cases = [
        sign("jws-compact-BP256R1", ["bp256r1"], "compact"),
        sign("jws-flattened-BP256R1", ["bp256r1"], "flattened"),
        sign("jws-general-BP256R1+BP256R1", ["bp256r1", "bp256r1"], "general"),
    ]
    write_json(out_path, {"library": LIBRARY, "cases": cases})


def verdict(case):
    try:
        if case["kind"] == "jws":
            if case["algs"] != ["BP256R1"] * len(case["algs"]):
                return "skipped: jwcrypto binds ES256 to P-256"
            for name in case["keys"]:
                token = jws.JWS()
                token.allowed_algs = SIGNATURE_ALGS
                token.deserialize(case["token"])
                token.verify(KEYS[name].public(), alg="BP256R1")
                if token.payload.decode() != case["payload"]:
                    return "failed: payload differs"
            return "ok"
        token = jwe.JWE()
        token.deserialize(case["token"], key=KEYS[case["keys"][0]])
        if token.payload.decode() != case["payload"]:
            return "failed: plaintext differs"
        return "ok"
    except Exception as e:  # the verdict records any refusal
        return f"failed: {type(e).__name__}: {e}"


def check(tokens_path, out_path):
    with open(tokens_path, "rb") as f:
        raw = f.read()
    tokens = json.loads(raw)
    results = {case["id"]: verdict(case) for case in tokens["cases"]}
    write_json(out_path, {"library": LIBRARY, "source": hashlib.sha256(raw).hexdigest(), "results": results})


if __name__ == "__main__":
    command = sys.argv[1]
    KEYS = read_keys(sys.argv[2])
    if command == "gen":
        gen(sys.argv[3])
    elif command == "check":
        check(sys.argv[3], sys.argv[4])
    else:
        sys.exit(f"unknown command {command}")
