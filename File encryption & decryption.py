import os
import sys
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from Cryptodome.Cipher import AES


# ==============================
# ENCRYPTION ENGINE
# ==============================
class EncryptionTool:
    def __init__(self, user_file, user_key, user_salt="default_salt"):

        self.user_file = user_file
        self.input_file_size = os.path.getsize(self.user_file)

        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert key + salt
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_salt[::-1], "utf-8")

        # file extension
        self.file_extension = self.user_file.split(".")[-1]

        # encrypted output
        self.encrypt_output_file = (
            ".".join(self.user_file.split(".")[:-1])
            + "." + self.file_extension + ".kryp"
        )

        # decrypted output
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(
            self.decrypt_output_file[:-1]
        ) + "__dekrypted__." + self.decrypt_output_file[-1]

        self.hashed_key_salt = {}
        self.hash_key_salt()

    # ==========================
    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    # ==========================
    def hash_key_salt(self):

        # KEY HASH
        hasher = hashlib.sha256()
        hasher.update(self.user_key)
        self.hashed_key_salt["key"] = hasher.digest()[:32]

        # SALT HASH
        hasher = hashlib.sha256()
        hasher.update(self.user_salt)
        self.hashed_key_salt["salt"] = hasher.digest()[:16]

    # ==========================
    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    # ==========================
    def encrypt(self):

        cipher = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CFB,
            self.hashed_key_salt["salt"],
        )

        self.abort()

        with open(self.user_file, "rb") as input_file, \
                open(self.encrypt_output_file, "ab") as output_file:

            done_chunks = 0

            for piece in self.read_in_chunks(input_file, self.chunk_size):
                output_file.write(cipher.encrypt(piece))
                done_chunks += 1
                yield (done_chunks / self.total_chunks) * 100

        del cipher

    # ==========================
    def decrypt(self):

        cipher = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CFB,
            self.hashed_key_salt["salt"],
        )

        self.abort()

        with open(self.user_file, "rb") as input_file, \
                open(self.decrypt_output_file, "xb") as output_file:

            done_chunks = 0

            for piece in self.read_in_chunks(input_file):
                output_file.write(cipher.decrypt(piece))
                done_chunks += 1
                yield (done_chunks / self.total_chunks) * 100

        del cipher


# ==============================
# GUI WINDOW
# ==============================
class MainWindow:

    if getattr(sys, "frozen", False):
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):

        self.root = root
        self._cipher = None

        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._status = tk.StringVar(value="---")

        self.should_cancel = False

        root.title("KrypApp")
        root.configure(bg="#eeeeee")
        root.geometry("420x360")

        # ===== FILE =====
        tk.Label(root,
                 text="Select File",
                 bg="#eeeeee").pack(pady=(10, 2))

        tk.Entry(root,
                 textvariable=self._file_url,
                 relief=tk.FLAT).pack(fill="x", padx=15, ipady=6)

        tk.Button(root,
                  text="SELECT FILE",
                  command=self.selectfile_callback,
                  bg="#1089ff",
                  fg="white").pack(fill="x", padx=15, pady=8)

        # ===== KEY =====
        tk.Label(root,
                 text="Secret Key",
                 bg="#eeeeee").pack()

        tk.Entry(root,
                 textvariable=self._secret_key,
                 show="*",
                 relief=tk.FLAT).pack(fill="x", padx=15, ipady=6)

        # ===== BUTTONS =====
        frame = tk.Frame(root, bg="#eeeeee")
        frame.pack(fill="x", padx=15, pady=10)

        tk.Button(frame,
                  text="ENCRYPT",
                  command=self.encrypt_callback,
                  bg="#ed3833",
                  fg="white").pack(side="left", expand=True, fill="x", padx=4)

        tk.Button(frame,
                  text="DECRYPT",
                  command=self.decrypt_callback,
                  bg="#00bd56",
                  fg="white").pack(side="left", expand=True, fill="x", padx=4)

        tk.Button(root,
                  text="RESET",
                  command=self.reset_callback,
                  bg="#aaaaaa",
                  fg="white").pack(fill="x", padx=15)

        # ===== STATUS =====
        tk.Label(root,
                 textvariable=self._status,
                 bg="#eeeeee",
                 wraplength=380).pack(pady=10)

    # ==========================
    def selectfile_callback(self):
        file = filedialog.askopenfile()
        if file:
            self._file_url.set(file.name)

    # ==========================
    def encrypt_callback(self):
        try:
            self._cipher = EncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )

            for p in self._cipher.encrypt():
                self._status.set(f"{p:.2f}%")
                self.root.update()

            self._status.set("File Encrypted!")

        except Exception as e:
            self._status.set(str(e))

    # ==========================
    def decrypt_callback(self):
        try:
            self._cipher = EncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )

            for p in self._cipher.decrypt():
                self._status.set(f"{p:.2f}%")
                self.root.update()

            self._status.set("File Decrypted!")

        except Exception as e:
            self._status.set(str(e))

    # ==========================
    def reset_callback(self):
        self._file_url.set("")
        self._secret_key.set("")
        self._status.set("---")


# ==============================
if __name__ == "__main__":
    ROOT = tk.Tk()
    MainWindow(ROOT)
    ROOT.mainloop()
