import tkinter as tk
from tkinter import scrolledtext
import threading

from network.client import (
    connect_to_server,
    send,
    recv
)

from protocol.session import (
    encrypt_message,
    decrypt_message
)


class SecureChatClient:

    def __init__(self, root):

        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")

        self.sock = None
        self.keys = None
        self.connected = False

        # =========================
        # Status
        # =========================
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Waiting...")

        status_label = tk.Label(
            root,
            textvariable=self.status_var,
            font=("Arial", 11, "bold"),
            anchor="w"
        )

        status_label.pack(fill="x", padx=10, pady=5)

        # =========================
        # Chat Box
        # =========================
        self.chat_box = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            state="disabled",
            font=("Arial", 11)
        )

        self.chat_box.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        # =========================
        # Bottom Frame
        # =========================
        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=10, pady=10)

        self.entry = tk.Entry(
            bottom,
            font=("Arial", 11)
        )

        self.entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.entry.bind(
            "<Return>",
            self.send_message
        )

        self.send_button = tk.Button(
            bottom,
            text="Send",
            width=10,
            command=self.send_message,
            state="disabled"
        )

        self.send_button.pack(
            side="left",
            padx=5
        )

        # =========================
        # Connect Button
        # =========================
        self.connect_button = tk.Button(
            root,
            text="Connect",
            width=15,
            command=self.connect
        )

        self.connect_button.pack(pady=5)

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

    # =====================================

    def add_message(self, sender, message):

        self.chat_box.configure(state="normal")

        self.chat_box.insert(
            tk.END,
            f"{sender}: {message}\n"
        )

        self.chat_box.configure(state="disabled")
        self.chat_box.see(tk.END)

    # =====================================

    def connect(self):

        self.status_var.set("Status: Connecting...")

        try:

            self.sock, self.keys = connect_to_server()

            if self.sock is None:

                self.status_var.set("Status: Disconnected")
                return

            self.connected = True

            self.status_var.set("Status: Connected")

            self.send_button.config(state="normal")

            self.connect_button.config(state="disabled")

            threading.Thread(
                target=self.receive_loop,
                daemon=True
            ).start()

        except Exception:

            self.status_var.set("Status: Disconnected")

    # =====================================

    def send_message(self, event=None):

        if not self.connected:
            return

        message = self.entry.get().strip()

        if message == "":
            return

        self.entry.delete(0, tk.END)

        self.add_message("You", message)

        print("You:", message)

        try:

            sequence, ciphertext, tag = encrypt_message(
                self.keys["c2s_key"],
                self.keys["nonce"],
                message.encode()
            )

            send(
                self.sock,
                sequence.to_bytes(8, "big")
            )

            send(
                self.sock,
                ciphertext
            )

            send(
                self.sock,
                tag
            )

        except Exception:

            self.status_var.set("Status: Disconnected")

            self.connected = False
    # =====================================

    def receive_loop(self):

        while self.connected:

            try:

                sequence = int.from_bytes(
                    recv(self.sock),
                    "big"
                )

                ciphertext = recv(self.sock)
                tag = recv(self.sock)

                message = decrypt_message(
                    self.keys["s2c_key"],
                    self.keys["nonce"],
                    sequence,
                    ciphertext,
                    tag
                )

                text = message.decode()

                print("Server:", text)

                self.root.after(
                    0,
                    lambda m=text: self.add_message("Server", m)
                )

            except Exception:

                self.connected = False

                try:
                    self.sock.close()
                except:
                    pass

                self.root.after(
                    0,
                    lambda: self.status_var.set("Status: Disconnected")
                )

                self.root.after(
                    0,
                    lambda: self.send_button.config(state="disabled")
                )

                self.root.after(
                    0,
                    lambda: self.connect_button.config(state="normal")
                )

                break

    # =====================================

    def close(self):

        self.connected = False

        if self.sock:

            try:
                self.sock.close()
            except:
                pass

        self.root.destroy()


# =========================================

def main():

    root = tk.Tk()

    SecureChatClient(root)

    root.mainloop()


if __name__ == "__main__":
    main()
