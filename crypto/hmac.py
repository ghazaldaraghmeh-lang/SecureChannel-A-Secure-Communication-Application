# hmac
from crypto.sha256 import sha256_from_scratch

BLOCK_SIZE = 64  # SHA-256 block size


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    # If the key is longer than 64 bytes, hash it first.
    if len(key) > BLOCK_SIZE:
        key = sha256_from_scratch(key)

    # Apply padding to the key
    key = key.ljust(BLOCK_SIZE, b'\x00')

    o_key_pad = bytes([b ^ 0x5c for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])

    inner = sha256_from_scratch(i_key_pad + message)
    return sha256_from_scratch(o_key_pad + inner)


if __name__ == "__main__":
    msg = b"hello world"
    key = b"secret"

    result = hmac_sha256(key, msg)

    print("HMAC-SHA256:", result.hex())
    
