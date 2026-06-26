# server

import socket

from protocol.handshake import (
    generate_ephemeral_keypair,
    compute_shared_secret,
    build_transcript,
    create_auth_tag,
    verify_auth_tag,
    derive_session_keys,
)

from protocol.session import (
    encrypt_message,
    decrypt_message
)

HOST = "127.0.0.1"
PORT = 5000

def send(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv(sock):
    size = int.from_bytes(sock.recv(4), "big")

    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))

    return data


def main():
    server = socket.socket()
    server.bind((HOST, PORT))
    server.listen(1)

    print("[SERVER] Waiting for connection...")

    conn, addr = server.accept()

    print("[SERVER] Connected:", addr)

    # 1. Receive client public key
    c_pub = recv(conn)

    # 2. Generate server key pair
    s_priv, s_pub = generate_ephemeral_keypair()

    # 3. Send server public key
    send(conn, s_pub)

    # 4. Compute shared secret
    shared_secret = compute_shared_secret(s_priv, c_pub)

    print("Shared Secret:", shared_secret.hex())

    # 5. Build transcript
    transcript = build_transcript(c_pub, s_pub)

    # 6. Verify client authentication
    client_tag = recv(conn)

    if not verify_auth_tag(client_tag, transcript):
        print("[SERVER] Client authentication failed")

        conn.close()
        server.close()
        return

    print("[SERVER] Client authenticated")

    # 7. Send server authentication tag
    server_tag = create_auth_tag(transcript)
    send(conn, server_tag)

    # 8. Derive session keys
    keys = derive_session_keys(shared_secret, transcript)

    print("\n[SERVER] Session established")
    print("C->S Key:", keys["c2s_key"].hex())
    print("S->C Key:", keys["s2c_key"].hex())
    print("Nonce   :", keys["nonce"].hex())

    # =========================
    # Receive Secure Message
    # =========================

    sequence = int.from_bytes(recv(conn), "big")
    ciphertext = recv(conn)
    tag = recv(conn)

    message = decrypt_message(
        keys["c2s_key"],
        keys["nonce"],
        sequence,
        ciphertext,
        tag
    )

    print("\n[SERVER] Client says:", message.decode())

    # =========================
    # Send Secure Reply
    # =========================

    sequence, ciphertext, tag = encrypt_message(
        keys["s2c_key"],
        keys["nonce"],
        b"Hello Client"
    )

    send(conn, sequence.to_bytes(8, "big"))
    send(conn, ciphertext)
    send(conn, tag)

    conn.close()
    server.close()


if __name__ == "__main__":
    main()
