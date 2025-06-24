import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_utils import generate_keys as real_generate_keys, encrypt_file as real_encrypt_file, decrypt_file as real_decrypt_file
import os


# Dummy functions – we'll replace these later
def generate_keys():
    try:
        priv, pub = real_generate_keys()
        messagebox.showinfo("Success", f"Keys generated:\n{priv}\n{pub}")
        status_label.config(text="Status: Keys generated", fg="#00FF00")
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed:\n{e}")
        status_label.config(text="Status: Key gen failed", fg="red")


def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if file_path:
        try:
            enc_path = real_encrypt_file(file_path)
            messagebox.showinfo("Success", f"File encrypted:\n{enc_path}")
            status_label.config(text="Status: File encrypted", fg="#00FF00")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")
            status_label.config(text="Status: Encryption failed", fg="red")


def decrypt_file():
    file_path = filedialog.askopenfilename(title="Select Encrypted File")
    if file_path:
        try:
            dec_path = real_decrypt_file(file_path)
            messagebox.showinfo("Success", f"File decrypted:\n{dec_path}")
            status_label.config(text="Status: File decrypted", fg="#00FF00")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            status_label.config(text="Status: Decryption failed", fg="red")


# Main GUI setup
root = tk.Tk()
root.title("File Encryptor")
root.geometry("400x400")
root.resizable(True, True)

title_label = tk.Label(root, text="🔐 File Encryptor", font=("Courier", 16))
title_label.pack(pady=25)

btn_generate = tk.Button(root, text="Generate Keys", width=45, command=generate_keys)
btn_generate.pack(pady=25)

btn_encrypt = tk.Button(root, text="Encrypt File", width=45, command=encrypt_file)
btn_encrypt.pack(pady=25)

btn_decrypt = tk.Button(root, text="Decrypt File", width=45, command=decrypt_file)
btn_decrypt.pack(pady=25)

status_label = tk.Label(root, text="Status: Ready", fg="blue")
status_label.pack(pady=20)

root.mainloop()
