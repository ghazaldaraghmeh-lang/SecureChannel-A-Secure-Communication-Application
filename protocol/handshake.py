# handshake

from crypto.x25519 import (
    generate_private_key,
    generate_public_key,
    x25519
)

from crypto.hkdf import hkdf_derive
from crypto.hmac import hmac_sha256

import hmac

PROTOCOL_VERSION = b"ENCS4320-v1"
PSK = b"my_super_secret_psk"


def build_transcript(
    client_pub,
    server_pub,
    client_id=b"client",
    server_id=b"server"
):
    return (
        PROTOCOL_VERSION +
        client_id +
        server_id +
        client_pub +
        server_pub
    )


def generate_ephemeral_keypair():
    priv = generate_private_key()
    pub = generate_public_key(priv)

    return priv, pub


def compute_shared_secret(
    private_key,
    peer_public
):
    return x25519(
        private_key,
        peer_public
    )


def create_auth_tag(transcript):
    return hmac_sha256(
        PSK,
        transcript
    )


def verify_auth_tag(
    tag,
    transcript
):
    expected = hmac_sha256(
        PSK,
        transcript
    )

    return hmac.compare_digest(
        tag,
        expected
    )


def derive_session_keys(
    shared_secret,
    transcript
):
    key_material = hkdf_derive(
        ikm=shared_secret,
        salt=PSK,
        info=transcript,
        length=76
    )

    return {
        "c2s_key": key_material[:32],
        "s2c_key": key_material[32:64],
        "nonce": key_material[64:76]
    }
