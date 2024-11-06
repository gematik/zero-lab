#! /usr/bin/env python3
# -*- coding: UTF-8 -*-

from base64 import b64encode
from binascii import hexlify
from cryptography.hazmat.primitives import hashes, hmac

import sys
import os
import time

if __name__ == '__main__':
    
    # get HMAC key from env variable
    hmac_key_hex = os.environ.get("VSDM_HMAC_KEY") or exit("VSDM_HMAC_KEY not set")
    hmac_key_kid = os.environ.get("VSDM_HMAC_KID") or exit("VSDM_HMAC_KID not set")

    hmac_key = bytes.fromhex(hmac_key_hex)

    if len(sys.argv) < 2:
        print("Usage: pn.py <kvnr>")
        sys.exit(1)

    if len(sys.argv[1]) != 10:
        print("kvnr must be 10 characters long")
        sys.exit(1)

    kvnr = sys.argv[1]

    iat = str(int(time.time()))

    print("HMAC key: ", hmac_key)
    print("HMAC key id: ", hmac_key_kid)
    print("KVNR: ", kvnr)
    print("IAT: ", iat)

    pn_string = f"{kvnr}{iat}U{hmac_key_kid}"

    if len(pn_string) != 23:
        print(f"pn_string must be 23 characters long: {pn_string}")
        sys.exit(1)

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(pn_string.encode())
    my_hmac_192Bit = h.finalize()[0:24]

    x = pn_string.encode() + my_hmac_192Bit
    pn = b64encode(x).decode()

    print("PN: ", pn)
    print("PN length: ", len(pn))
