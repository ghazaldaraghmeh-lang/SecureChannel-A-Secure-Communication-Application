# test_sha256.py

import hashlib
from sha256 import sha256_from_scratch


def test(message: bytes):
    my_hash = sha256_from_scratch(message).hex()
    real_hash = hashlib.sha256(message).hexdigest()

    print(f"Message: {message}")
    print(f"My Hash:     {my_hash}")
    print(f"Python Hash: {real_hash}")

    if my_hash == real_hash:
        print("PASS\n")
    else:
        print("FAIL\n")


test(b"")
test(b"abc")
test(b"Hello World")
test(b"a" * 1000)
