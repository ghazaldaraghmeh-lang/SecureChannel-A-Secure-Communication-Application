# client

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
    sock = socket.socket()
    sock.connect((HOST, PORT))

    # 1. Generate ephemeral key pair
    c_priv, c_pub = generate_ephemeral_keypair()

    # 2. Send client public key
    send(sock, c_pub)

    # 3. Receive server public key
    s_pub = recv(sock)

    # 4. Compute shared secret
    shared_secret = compute_shared_secret(c_priv, s_pub)

    print("Shared Secret:", shared_secret.hex())

    # 5. Build transcript
    transcript = build_transcript(c_pub, s_pub)

    # 6. Send authentication tag
    client_tag = create_auth_tag(transcript)
    send(sock, client_tag)

    # 7. Receive server authentication tag
    server_tag = recv(sock)

    if not verify_auth_tag(server_tag, transcript):
        print("[CLIENT] Server authentication failed")
        sock.close()
        return

    print("[CLIENT] Server authenticated")

    # 8. Derive session keys
    keys = derive_session_keys(shared_secret, transcript)

    print("\n[CLIENT] Session established")
    print("C->S Key:", keys["c2s_key"].hex())
    print("S->C Key:", keys["s2c_key"].hex())
    print("Nonce   :", keys["nonce"].hex())

    # =========================
    # Send Secure Message
    # =========================

    sequence, ciphertext, tag = encrypt_message(
        keys["c2s_key"],
        keys["nonce_seed"],
        b"Hello Server"
    )

    send(sock, sequence.to_bytes(8, "big"))
    send(sock, ciphertext)
    send(sock, tag)

    # =========================
    # Receive Secure Reply
    # =========================

    sequence = int.from_bytes(recv(sock), "big")
    ciphertext = recv(sock)
    tag = recv(sock)

    message = decrypt_message(
        keys["s2c_key"],
        keys["nonce_seed"],
        sequence,
        ciphertext,
        tag
    )

    print("\n[CLIENT] Server says:", message.decode())


    sock.close()


if __name__ == "__main__":
    main()
