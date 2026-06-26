# aead

import struct

from crypto.chacha20 import (
    chacha20_block,
    chacha20_encrypt,
)

from crypto.poly1305 import (
    poly1305_mac,
)


def pad16(data: bytes) -> bytes:
    """
    RFC 8439 padding.
    """
    if len(data) % 16 == 0:
        return b""

    return b"\x00" * (16 - (len(data) % 16))


def build_mac_data(
        aad: bytes,
        ciphertext: bytes
) -> bytes:

    return (
        aad
        + pad16(aad)
        + ciphertext
        + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def generate_poly1305_key(
        key: bytes,
        nonce: bytes
) -> bytes:
    """
    First 32 bytes of ChaCha20 block(counter=0)
    """

    block = chacha20_block(
        key,
        counter=0,
        nonce=nonce
    )

    return block[:32]


def aead_encrypt(
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b""
):

    poly_key = generate_poly1305_key(
        key,
        nonce
    )

    ciphertext = chacha20_encrypt(
        key,
        nonce,
        plaintext,
        counter=1
    )

    mac_data = build_mac_data(
        aad,
        ciphertext
    )

    tag = poly1305_mac(
        poly_key,
        mac_data
    )

    return ciphertext, tag


def aead_decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b""
):

    poly_key = generate_poly1305_key(
        key,
        nonce
    )

    mac_data = build_mac_data(
        aad,
        ciphertext
    )

    expected_tag = poly1305_mac(
        poly_key,
        mac_data
    )

    if expected_tag != tag:
        raise ValueError(
            "Authentication failed"
        )

    plaintext = chacha20_encrypt(
        key,
        nonce,
        ciphertext,
        counter=1
    )

    return plaintext



if __name__ == "__main__":

    key = bytes(range(32))

    nonce = bytes.fromhex(
        "000000000000000000000001"
    )

    aad = b"header"

    plaintext = b"Hello SecureChannel"

    ciphertext, tag = aead_encrypt(
        key,
        nonce,
        plaintext,
        aad
    )

    recovered = aead_decrypt(
        key,
        nonce,
        ciphertext,
        tag,
        aad
    )

    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())
    print("Recovered:", recovered)
    print("Success:", recovered == plaintext)# aead

import struct

from chacha20 import (
    chacha20_block,
    chacha20_encrypt,
)

from poly1305 import (
    poly1305_mac,
)


def pad16(data: bytes) -> bytes:
    """
    RFC 8439 padding.
    """
    if len(data) % 16 == 0:
        return b""

    return b"\x00" * (16 - (len(data) % 16))


def build_mac_data(
        aad: bytes,
        ciphertext: bytes
) -> bytes:

    return (
        aad
        + pad16(aad)
        + ciphertext
        + pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def generate_poly1305_key(
        key: bytes,
        nonce: bytes
) -> bytes:
    """
    First 32 bytes of ChaCha20 block(counter=0)
    """

    block = chacha20_block(
        key,
        counter=0,
        nonce=nonce
    )

    return block[:32]


def aead_encrypt(
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: bytes = b""
):

    poly_key = generate_poly1305_key(
        key,
        nonce
    )

    ciphertext = chacha20_encrypt(
        key,
        nonce,
        plaintext,
        counter=1
    )

    mac_data = build_mac_data(
        aad,
        ciphertext
    )

    tag = poly1305_mac(
        poly_key,
        mac_data
    )

    return ciphertext, tag


def aead_decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b""
):

    poly_key = generate_poly1305_key(
        key,
        nonce
    )

    mac_data = build_mac_data(
        aad,
        ciphertext
    )

    expected_tag = poly1305_mac(
        poly_key,
        mac_data
    )

    if expected_tag != tag:
        raise ValueError(
            "Authentication failed"
        )

    plaintext = chacha20_encrypt(
        key,
        nonce,
        ciphertext,
        counter=1
    )

    return plaintext



if __name__ == "__main__":

    key = bytes(range(32))

    nonce = bytes.fromhex(
        "000000000000000000000001"
    )

    aad = b"header"

    plaintext = b"Hello SecureChannel"

    ciphertext, tag = aead_encrypt(
        key,
        nonce,
        plaintext,
        aad
    )

    recovered = aead_decrypt(
        key,
        nonce,
        ciphertext,
        tag,
        aad
    )

    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())
    print("Recovered:", recovered)
    print("Success:", recovered == plaintext)
