import socket
import secrets

from x25519 import (
    generate_private_key,
    generate_public_key,
    x25519
)

from hkdf import hkdf_derive
from hmac_ref import hmac_sha256
from sha256 import sha256_from_scratch

# =========================
HOST = "127.0.0.1"
PORT = 5000

PROTOCOL_VERSION = b"ENCS4320-v1"

PSK = b"my_super_secret_psk"

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

    # 3. Receive server pubkeyPS C:\Users\Lenovo\Desktop\....> python handshake.py
    # Run as (c)lient or (s)erver? c
    # SHARED: 6ccb663fa0d42e634a4215943514d6b96f23b98fe91bc86dfd3bb98c311b9b79
    # [CLIENT]  Server authenticated
    # [CLIENT] Shared session established
    # C->S Key: 7fdee66a720e3423296d285b781100a3fe60704c14dce2ae71379281e30fb4fb
    # S->C Key: aa67ed59e79e2f2ba8a8f544233ff8e1b47a53f8fac64a4f8c0447a7dbeb02f0
    # Nonce   : 0749c0dfca41c874d4f32d18deac4937de2b7cce0bc5012a66dd7777abfebed6

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

    conn.close()
    sock.close()
# =========================
if __name__ == "__main__":
    mode = input("Run as (c)lient or (s)erver? ").strip().lower()

    if mode == "c":
        client()
    else:
        server()
