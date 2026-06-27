# client

import socket
import threading

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

def sender(sock, keys):
    while True:
        try:
            msg = input("You: ")

            if msg.lower() == "exit":
                sock.close()
                break

            sequence, ciphertext, tag = encrypt_message(
                keys["c2s_key"],
                keys["nonce"],
                msg.encode()
            )

            send(sock, sequence.to_bytes(8, "big"))
            send(sock, ciphertext)
            send(sock, tag)
            
        except Exception:
            print("[CLIENT] Unable to send message.")
            break
            
def receiver(sock, keys):
    while True:
        try:
            sequence = int.from_bytes(recv(sock), "big")
            ciphertext = recv(sock)
            tag = recv(sock)

            message = decrypt_message(
                keys["s2c_key"],
                keys["nonce"],
                sequence,
                ciphertext,
                tag
            )

            print("\nServer:", message.decode())

        except:
            print("[CLIENT] Connection closed.")
            try:
                sock.close()
            except:
                pass
            break

def connect_to_server():
    try:
        sock = socket.socket()
        sock.connect((HOST, PORT))
        
        print("[CLIENT] Connected to server")

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
            return None, None

        print("[CLIENT] Server authenticated")

        keys = derive_session_keys(shared_secret, transcript)

        print("\n[CLIENT] Session established")
        print("C->S Key:", keys["c2s_key"].hex())
        print("S->C Key:", keys["s2c_key"].hex())
        print("Nonce   :", keys["nonce"].hex())

        return sock, keys
    
    except Exception as e:
        print("[CLIENT]", e)
        return None, None

def main():
    
    sock, keys = connect_to_server()
    
    if sock is None:
        return
    
    
    send_thread = threading.Thread(
        target=sender,
        args=(sock, keys)
    )

    recv_thread = threading.Thread(
        target=receiver,
        args=(sock, keys),
        daemon=True
    )

    recv_thread.start()
    send_thread.start()

    send_thread.join()
     
  
    sock.close()


if __name__ == "__main__":
    main()
