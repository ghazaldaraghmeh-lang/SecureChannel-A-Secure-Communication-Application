import socket
import secrets
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from x25519 import (
    generate_private_key,
    generate_public_key,
    x25519
)

from hkdf import hkdf_derive
from hmac_ref import hmac_sha256
from sha256 import sha256_from_scratch

# =========================
# CONFIG
# =========================
HOST = "127.0.0.1"
PORT = 5000

PROTOCOL_VERSION = b"ENCS4320-v1"

PSK = b"my_super_secret_psk"


# =========================
# HELPERS
# =========================
def build_transcript(client_pub, server_pub, client_id=b"client", server_id=b"server"):
    return PROTOCOL_VERSION + client_id + server_id + client_pub + server_pub


def send(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv(sock):
    size = int.from_bytes(sock.recv(4), "big")
    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))
    return data
# =========================
# CHACHA20-POLY1305
# =========================

def encrypt_message(key, message: str):
    cipher = ChaCha20Poly1305(key)

    nonce = os.urandom(12)

    ciphertext = cipher.encrypt(
        nonce,
        message.encode(),
        None
    )

    return nonce, ciphertext


def decrypt_message(key, nonce, ciphertext):
    cipher = ChaCha20Poly1305(key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()

# =========================
# CLIENT SIDE
# =========================
def client():
    sock = socket.socket()
    sock.connect((HOST, PORT))

    # 1. Ephemeral X25519 keys
    c_priv = generate_private_key()
    c_pub = generate_public_key(c_priv)

    # 2. Send client pubkey
    send(sock, c_pub)

    s_pub = recv(sock)

    # 4. Compute shared secret
    shared_secret = x25519(c_priv, s_pub)
    print("SHARED:", shared_secret.hex())

    # 5. Build transcript
    transcript = build_transcript(c_pub, s_pub)

    # 6. HMAC authentication tag
    client_tag = hmac_sha256(PSK, transcript)
    send(sock, client_tag)

    # 7. Receive server tag
    server_tag = recv(sock)

    expected_server_tag = hmac_sha256(PSK, transcript)

    if server_tag != expected_server_tag:
        print("[CLIENT] Handshake failed (server auth invalid)")
        sock.close()
        return

    print("[CLIENT] Server authenticated")

    # 8. HKDF key derivation
    key_material = hkdf_derive(
        ikm=shared_secret,
        salt=PSK,
        info=transcript,
        length=96
    )

    c2s_key = key_material[:32]
    s2c_key = key_material[32:64]
    nonce   = key_material[64:96]


    print("[CLIENT] Shared session established")
    print("C->S Key:", c2s_key.hex())
    print("S->C Key:", s2c_key.hex())
    print("Nonce   :", nonce.hex())

    # =========================
    # PHASE B: Send encrypted message
    # =========================

    nonce, ciphertext = encrypt_message(
        c2s_key,
        "Hello Server"
    )

    send(sock, nonce)
    send(sock, ciphertext)

    print("[CLIENT] Encrypted message sent")

    sock.close()


# =========================
# SERVER SIDE
# =========================
def server():
    sock = socket.socket()
    sock.bind((HOST, PORT))
    sock.listen(1)
    print("[SERVER] Waiting for client connection...")
    conn, _ = sock.accept()

    # 1. Receive client pubkey
    c_pub = recv(conn)

    # 2. Generate server key pair
    s_priv = generate_private_key()
    s_pub = generate_public_key(s_priv)

    # 3. Send server pubkey
    send(conn, s_pub)

    # 4. Compute shared secret
    shared_secret = x25519(s_priv, c_pub)
    print("SHARED:", shared_secret.hex())

    # 5. Build transcript
    transcript = build_transcript(c_pub, s_pub)

    # 6. Receive client tag
    client_tag = recv(conn)
    expected_client_tag = hmac_sha256(PSK, transcript)

    if client_tag != expected_client_tag:
        print("[SERVER] Handshake failed (client auth invalid)")
        conn.close()
        return

    print("[SERVER]  Client authenticated")

    # 7. Send server tag
    server_tag = hmac_sha256(PSK, transcript)
    send(conn, server_tag)

    # 8. HKDF key derivation
    key_material = hkdf_derive(
        ikm=shared_secret,
        salt=PSK,
        info=transcript,
        length=96
    )

    c2s_key = key_material[:32]
    s2c_key = key_material[32:64]
    nonce   = key_material[64:96]

    print("[SERVER] Shared session established")
    print("C->S Key:", c2s_key.hex())
    print("S->C Key:", s2c_key.hex())
    print("Nonce   :", nonce.hex())

    # =========================
    # PHASE B: Receive encrypted message
    # =========================

    received_nonce = recv(conn)
    received_ciphertext = recv(conn)

    message = decrypt_message(
        c2s_key,
        received_nonce,
        received_ciphertext
    )

    print("[SERVER] Decrypted message:", message)
    conn.close()
    sock.close()


# =========================
# RUN MODE
# =========================
if __name__ == "__main__":
    mode = input("Run as (c)lient or (s)erver? ").strip().lower()

    if mode == "c":
        client()
    else:
        server()

    # 3. Receive server pubkeyPS C:\Users\Lenovo\Desktop\....> python handshake.py
    # Run as (c)lient or (s)erver? c
    # SSHARED: 319ede3709977719e7fbe11cde0e72e249fd1f1fc9772970852262bc7c324d4c
    # [CLIENT]  Server authenticated
    # [CLIENT] Shared session established
    # C->S Key: b74fc95ebd3d94b09d2582cdb89f6b0048f5b8b36d4f0ecf2cf2bd63c77b652f
    # S->C Key:  bf312fbc991da275468b369147ef30f18456280a9d51713b026a5a61b94a0f6a
    # Nonce   : 8d40ef86a8162590c14af6472fbfaa67394445d0e6455129b704946bf9570ace
    #[CLIENT] Encrypted message sent
    #Run as (c)lient or (s)erver? s
#[SERVER] Waiting for client connection...
#SHARED: 319ede3709977719e7fbe11cde0e72e249fd1f1fc9772970852262bc7c324d4c
#[SERVER]  Client authenticated
#[SERVER] Shared session established
#C->S Key: b74fc95ebd3d94b09d2582cdb89f6b0048f5b8b36d4f0ecf2cf2bd63c77b652f
#S->C Key: bf312fbc991da275468b369147ef30f18456280a9d51713b026a5a61b94a0f6a
#Nonce   : 8d40ef86a8162590c14af6472fbfaa67394445d0e6455129b704946bf9570ace
#[SERVER] Decrypted message: Hello Server
