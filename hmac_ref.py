import hashlib

BLOCK_SIZE = 64  # SHA-256 block size


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    # إذا المفتاح أطول من 64 بايت -> نعمله hash أولاً
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()

    # padding للمفتاح
    key = key.ljust(BLOCK_SIZE, b'\x00')

    o_key_pad = bytes([b ^ 0x5c for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])

    inner = hashlib.sha256(i_key_pad + message).digest()
    return hashlib.sha256(o_key_pad + inner).digest()


if __name__ == "__main__":
    msg = b"hello world"
    key = b"secret"

    result = hmac_sha256(key, msg)

    print("HMAC-SHA256:", result.hex())
    