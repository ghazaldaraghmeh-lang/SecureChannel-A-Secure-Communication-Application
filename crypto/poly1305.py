def le_bytes_to_num(b):
    return int.from_bytes(b, "little")


def num_to_16_bytes(n):
    return n.to_bytes(16, "little")


class Poly1305:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")

        r = le_bytes_to_num(key[:16])
        s = le_bytes_to_num(key[16:])

        r &= 0x0ffffffc0ffffffc0ffffffc0fffffff  # clamp

        self.r = r
        self.s = s
        self.acc = 0

    def update(self, msg: bytes):
        p = 1 << 130
        mod = p - 5

        for i in range(0, len(msg), 16):
            block = msg[i:i+16]

            n = le_bytes_to_num(block + b"\x01")

            self.acc = (self.acc + n) * self.r
            self.acc %= mod

    def finalize(self):
        tag = (self.acc + self.s) % (1 << 128)
        return num_to_16_bytes(tag)


def poly1305_mac(key: bytes, msg: bytes) -> bytes:
    p = Poly1305(key)
    p.update(msg)
    return p.finalize()