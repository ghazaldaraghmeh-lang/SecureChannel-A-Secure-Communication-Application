import tkinter as tk
from tkinter import scrolledtext
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


class ServerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Server")
        self.root.geometry("600x500")

        self.server = None
        self.conn = None
        self.keys = None
        self.running = False

        # ================= STATUS =================
        self.status = tk.StringVar(value="Status: Waiting...")

        tk.Label(
            root,
            textvariable=self.status,
            font=("Arial", 11, "bold")
        ).pack(fill="x", padx=10, pady=5)

        # ================= CHAT BOX =================
        self.chat = scrolledtext.ScrolledText(root, state="disabled")
        self.chat.pack(fill="both", expand=True, padx=10, pady=5)

        # ================= INPUT =================
        frame = tk.Frame(root)
        frame.pack(fill="x", padx=10, pady=10)

        self.entry = tk.Entry(frame)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(
            frame,
            text="Send",
            state="disabled",
            command=self.send_message
        )
        self.send_btn.pack(side="left", padx=5)

        # ================= START BUTTON =================
        self.start_btn = tk.Button(
            root,
            text="Start Server",
            command=self.start_server
        )
        self.start_btn.pack(pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.close)

    # ================= UI HELPERS =================

    def add_message(self, sender, msg):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, f"{sender}: {msg}\n")
        self.chat.config(state="disabled")
        self.chat.see(tk.END)

    # ================= START SERVER =================

    def start_server(self):
        self.status.set("Status: Waiting for client...")
        threading.Thread(target=self.server_loop, daemon=True).start()

    def server_loop(self):
        self.server = socket.socket()
        self.server.bind((HOST, PORT))
        self.server.listen(1)

        self.conn, addr = self.server.accept()

        print("[SERVER] Connected:", addr)
        self.status.set("Status: Connected")

        # ===== HANDSHAKE =====
        s_priv, s_pub = generate_ephemeral_keypair()

        c_pub = recv(self.conn)
        send(self.conn, s_pub)

        shared_secret = compute_shared_secret(s_priv, c_pub)
        transcript = build_transcript(c_pub, s_pub)

        client_tag = recv(self.conn)

        if not verify_auth_tag(client_tag, transcript):
            print("[SERVER] Auth failed")
            self.conn.close()
            return

        server_tag = create_auth_tag(transcript)
        send(self.conn, server_tag)

        self.keys = derive_session_keys(shared_secret, transcript)

        print("[SERVER] Session established")

        self.running = True
        self.send_btn.config(state="normal")

        threading.Thread(target=self.receive_loop, daemon=True).start()

    # ================= RECEIVE LOOP =================

    def receive_loop(self):

        while self.running:
            try:
                seq = int.from_bytes(recv(self.conn), "big")
                ct = recv(self.conn)
                tag = recv(self.conn)

                msg = decrypt_message(
                    self.keys["c2s_key"],
                    self.keys["nonce"],
                    seq,
                    ct,
                    tag
                ).decode()

                print("Client:", msg)

                self.root.after(
                    0,
                    lambda m=msg: self.add_message("Client", m)
                )

            except Exception:
                print("[SERVER] Client disconnected")
                self.running = False
                break

    # ================= SEND MESSAGE =================

    def send_message(self, event=None):

        if not self.running:
            return

        msg = self.entry.get().strip()
        if not msg:
            return

        self.entry.delete(0, tk.END)

        self.add_message("You", msg)
        print("You:", msg)

        try:
            seq, ct, tag = encrypt_message(
                self.keys["s2c_key"],
                self.keys["nonce"],
                msg.encode()
            )

            send(self.conn, seq.to_bytes(8, "big"))
            send(self.conn, ct)
            send(self.conn, tag)

        except Exception:
            print("[SERVER] Send failed")
            self.running = False

    # ================= CLOSE =================

    def close(self):
        self.running = False
        try:
            if self.conn:
                self.conn.close()
            if self.server:
                self.server.close()
        except:
            pass
        self.root.destroy()


# ================= MAIN =================

def main():
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
