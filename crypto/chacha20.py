# chacha20

import struct

# RFC 8439 constants
CONSTANTS = [
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
]


def rotate_left(value: int, shift: int) -> int:
    return (
        ((value << shift) & 0xffffffff)
        | (value >> (32 - shift))
    )


def quarter_round(a, b, c, d):

    a = (a + b) & 0xffffffff
    d ^= a
    d = rotate_left(d, 16)

    c = (c + d) & 0xffffffff
    b ^= c
    b = rotate_left(b, 12)

    a = (a + b) & 0xffffffff
    d ^= a
    d = rotate_left(d, 8)

    c = (c + d) & 0xffffffff
    b ^= c
    b = rotate_left(b, 7)

    return a, b, c, d


def initialize_state(
        key: bytes,
        counter: int,
        nonce: bytes):

    return (
        CONSTANTS
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce))
    )


def chacha20_block(
        key: bytes,
        counter: int,
        nonce: bytes):

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    state = initialize_state(
        key,
        counter,
        nonce
    )

    working = state.copy()

    for _ in range(10):

        # Column rounds
        working[0], working[4], working[8], working[12] = \
            quarter_round(working[0], working[4], working[8], working[12])

        working[1], working[5], working[9], working[13] = \
            quarter_round(working[1], working[5], working[9], working[13])

        working[2], working[6], working[10], working[14] = \
            quarter_round(working[2], working[6], working[10], working[14])

        working[3], working[7], working[11], working[15] = \
            quarter_round(working[3], working[7], working[11], working[15])

        # Diagonal rounds
        working[0], working[5], working[10], working[15] = \
            quarter_round(working[0], working[5], working[10], working[15])

        working[1], working[6], working[11], working[12] = \
            quarter_round(working[1], working[6], working[11], working[12])

        working[2], working[7], working[8], working[13] = \
            quarter_round(working[2], working[7], working[8], working[13])

        working[3], working[4], working[9], working[14] = \
            quarter_round(working[3], working[4], working[9], working[14])

    final_state = []

    for i in range(16):
        final_state.append(
            (working[i] + state[i]) & 0xffffffff
        )

    return struct.pack("<16I", *final_state)


def chacha20_encrypt(
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        counter: int = 1):

    ciphertext = bytearray()

    for offset in range(0, len(plaintext), 64):

        block = plaintext[offset:offset + 64]

        keystream = chacha20_block(
            key,
            counter,
            nonce
        )

        counter += 1

        ciphertext.extend(
            p ^ k
            for p, k in zip(block, keystream)
        )

    return bytes(ciphertext)


def chacha20_decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        counter: int = 1):

    return chacha20_encrypt(
        key,
        nonce,
        ciphertext,
        counter
    )
