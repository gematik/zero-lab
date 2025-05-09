#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# /// script
# dependencies = [
#   "httpx",
#   "rich",
#   "jwcrypto",
#   "pydantic",
# ]
# ///

# Usage:
#  uv run --no-project test.py

import base64
import hashlib
import os
import subprocess
import time

import httpx
from jwcrypto import jwk, jwt
from pydantic import BaseModel
from rich.console import Console


def request_to_curl(request: httpx.Request) -> str:
    """
    Convert an httpx request to a curl command.
    """
    curl_command = [f"curl -X {request.method}"]
    for header, value in request.headers.items():
        curl_command.append(f"-H '{header}: {value}'")

    curl_command.append(str(request.url))
    if request.method in ["POST", "PUT", "PATCH"]:
        curl_command.append("-d")
        curl_command.append(request.content.decode("utf-8"))

    return " \\\n    ".join(curl_command)


PDP_WORKDIR = "~/.config/telematik"
PDP_SRC = "../pdp"
TOKEN_AUD = "http://127.0.0.1:8010"
TOKEN_SCOPE = "protected"
TOKEN_CLIENT_ID = "pdp-client"
TOKEN_SUB = "pdp-client"

console = Console()

# Set environment variable
os.environ["PDP_WORKDIR"] = os.path.expanduser(PDP_WORKDIR)

# Change to the PDP_SRC directory
pdp_src_path = os.path.abspath(PDP_SRC)
os.chdir(pdp_src_path)

# Execute a command in the directory
command = [
    "go",
    "run",
    "./cmd/zero-pdp",
    "non-prod",
    "issue",
    "-a",
    TOKEN_AUD,
    "-s",
    TOKEN_SCOPE,
    "-c",
    TOKEN_CLIENT_ID,
    "-u",
    TOKEN_SUB,
]
result = subprocess.run(command, capture_output=True, text=True)

if result.returncode != 0:
    console.print(result.stderr, style="bold red")
    exit(1)


class TokenData(BaseModel):
    token_response: dict
    dpop_key: dict


token_data = TokenData.model_validate_json(result.stdout)

# calculate access_token hash
# Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.

access_token = token_data.token_response["access_token"]

access_token_hash_bytes = hashlib.sha256(access_token.encode("ascii")).digest()
access_token_hash = (
    base64.urlsafe_b64encode(access_token_hash_bytes).decode("ascii").rstrip("=")
)

dpop_key = jwk.JWK(**token_data.dpop_key)
console.print("dpop_key:", dpop_key.export(private_key=False), style="bold green")

# create and sign dpop token
dpop_proof = jwt.JWT(
    header={"alg": "ES256", "typ": "dpop+jwt", "jwk": dpop_key.public()},
    claims={
        "jti": "dpop-proof",
        "htm": "GET",
        "htu": "http://127.0.0.1:8010/protected-dpop",
        "iat": int(time.time()),
        "ath": access_token_hash,
    },
)

dpop_proof.make_signed_token(dpop_key)
dpop_proof_token = dpop_proof.serialize(compact=True)

# create request with DPoP proof
request = httpx.Request(
    "GET",
    "http://127.0.0.1:8010/protected-dpop",
)

request.headers["Authorization"] = f"DPoP {token_data.token_response['access_token']}"
request.headers["DPoP"] = dpop_proof_token

console.print("Request:", request_to_curl(request), style="bold blue")
# send request
client = httpx.Client()
response = client.send(request)
if response.status_code == 200:
    console.print("Response:", response.text)
else:
    console.print("Error:", response.status_code, style="bold red")
    console.print(response.text, style="bold red")
