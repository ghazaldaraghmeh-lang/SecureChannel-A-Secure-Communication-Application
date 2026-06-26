from crypto.aead import (
    aead_encrypt,
    aead_decrypt
)



# ============================================================
# Session State
# ============================================================

_send_sequence = 0
_expected_sequence = 0


# ============================================================
# Nonce Generation
# ============================================================

def make_nonce(
    nonce_seed: bytes,
    sequence: int
) -> bytes:

    nonce = bytearray(nonce_seed)

    sequence_bytes = sequence.to_bytes(
        8,
        "little"
    )

    for i in range(8):
        nonce[4 + i] ^= sequence_bytes[i]

    return bytes(nonce)


# ============================================================
# Additional Authenticated Data (AAD)
# ============================================================

def build_aad(
    sequence: int,
    message_type: int = 1
) -> bytes:

    aad = (
        sequence.to_bytes(8, "big") +
        message_type.to_bytes(1, "big")
    )

    return aad


# ============================================================
# Encrypt
# ============================================================

def encrypt_message(
    key: bytes,
    nonce_seed: bytes,
    plaintext: bytes,
    message_type: int = 1
):

    global _send_sequence

    sequence = _send_sequence

    nonce = make_nonce(
        nonce_seed,
        sequence
    )

    aad = build_aad(
        sequence,
        message_type
    )

    ciphertext, tag = aead_encrypt(
        key,
        nonce,
        plaintext,
        aad
    )

    _send_sequence += 1

    return (
        sequence,
        ciphertext,
        tag
    )


# ============================================================
# Decrypt
# ============================================================

def decrypt_message(
    key: bytes,
    nonce_seed: bytes,
    sequence: int,
    ciphertext: bytes,
    tag: bytes,
    message_type: int = 1
):

    global _expected_sequence

    # Replay protection

    if sequence != _expected_sequence:
        raise ValueError(
            "Replay attack or invalid sequence number."
        )

    nonce = make_nonce(
        nonce_seed,
        sequence
    )

    aad = build_aad(
        sequence,
        message_type
    )

    plaintext = aead_decrypt(
        key,
        nonce,
        ciphertext,
        tag,
        aad
    )

    _expected_sequence += 1

    return plaintext


# ============================================================
# Reset Session
# ============================================================

def reset_session():

    global _send_sequence
    global _expected_sequence

    _send_sequence = 0
    _expected_sequence = 0
