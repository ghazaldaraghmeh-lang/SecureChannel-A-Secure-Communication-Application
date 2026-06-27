# test_sha256.py

import hashlib
from crypto.sha256 import sha256_from_scratch


def run_test(message: bytes, expected_hex: str | None = None):
    my_hash = sha256_from_scratch(message).hex()
    real_hash = hashlib.sha256(message).hexdigest()

    print("=" * 60)
    print(f"Message: {message}")

    print(f"My Hash:     {my_hash}")
    print(f"Python Hash: {real_hash}")

    # 1. Compare with hashlib (main guarantee)
    assert my_hash == real_hash, "Mismatch with hashlib!"

    # 2. Optional: compare with known expected value
    if expected_hex:
        assert my_hash == expected_hex, "Mismatch with expected vector!"

    print("PASS")


def main():
    # RFC / standard test vectors
    run_test(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    
    run_test(b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    run_test(
        b"Hello World",
        "a591a6d40bf420404a011733cfb7b190"
        "d62c65bf0bcda32b57b277d9ad9f146e"
    )

    run_test(b"a" * 1000)  # no need expected (hashlib check is enough)

    run_test(b"\x00\xff\x01\x02")  # edge case

    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    main()
