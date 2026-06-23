from x25519 import generate_private_key, generate_public_key, x25519
from hkdf import hkdf_derive


PSK = b"my_super_secret_psk"
INFO = b"SecureChannel-v1"


def perform_handshake():
    # ======================
    # 1. Alice keys
    # ======================
    alice_priv = generate_private_key()
    alice_pub = generate_public_key(alice_priv)

    # ======================
    # 2. Bob keys
    # ======================
    bob_priv = generate_private_key()
    bob_pub = generate_public_key(bob_priv)

    # ======================
    # 3. X25519 shared secret
    # ======================
    alice_shared = x25519(alice_priv, bob_pub)
    bob_shared = x25519(bob_priv, alice_pub)

    assert alice_shared == bob_shared, "Key exchange failed!"

    # ======================
    # 4. HKDF -> session keys
    # ======================
    alice_session = hkdf_derive(alice_shared, PSK, INFO, 96)
    bob_session   = hkdf_derive(bob_shared, PSK, INFO, 96)

    assert alice_session == bob_session, "HKDF mismatch!"

    # ======================
    # 5. Split keys
    # ======================
    session_key = alice_session[:32]
    nonce = alice_session[64:96]

    return {
        "shared_secret": alice_shared,
        "session_key": session_key,
        "nonce": nonce,
        "alice_pub": alice_pub,
        "bob_pub": bob_pub
    }


if __name__ == "__main__":
    result = perform_handshake()

    print("✔ Handshake successful")
    print("Shared Secret :", result["shared_secret"].hex())
    print("Session Key   :", result["session_key"].hex())
    print("Nonce         :", result["nonce"].hex())