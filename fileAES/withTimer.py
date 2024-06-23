import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk

class AESFileEncryptor:
    def __init__(self, key):
        self.key = key
        self.backend = default_backend()
    
    def _pad_data(self, data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data
    
    def _unpad_data(self, data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    
    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padded_plaintext = self._pad_data(plaintext)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext
    
    def decrypt(self, ciphertext):
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        plaintext = self._unpad_data(padded_plaintext)
        return plaintext

def select_file():
    file_path = filedialog.askopenfilename()
    return file_path

def get_key(key_length):
    key = simpledialog.askstring("Input", f"Enter the encryption key (must be {key_length} bytes):")
    if len(key) != key_length:
        messagebox.showerror("Error", f"Invalid key length. Key must be {key_length} bytes long.")
        return None
    return key.encode('utf-8')

def process_file(operation, key_length, result_label):
    file_path = select_file()
    if not file_path:
        return
    
    key = get_key(key_length)
    if not key:
        return
    
    encryptor = AESFileEncryptor(key)
    
    with open(file_path, 'rb') as file:
        data = file.read()
    
    start_time = time.time()
    if operation == "encrypt":
        processed_data = encryptor.encrypt(data)
    elif operation == "decrypt":
        processed_data = encryptor.decrypt(data)
    else:
        raise ValueError("Invalid operation")
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    
    output_file_path = filedialog.asksaveasfilename()
    if output_file_path:
        with open(output_file_path, 'wb') as file:
            file.write(processed_data)
        messagebox.showinfo("Success", f"File has been {operation}ed and saved successfully.")
    
    result_label.config(text=f"Time taken for {operation}: {elapsed_time:.6f} seconds")

def create_gui():
    root = tk.Tk()
    root.title("AES File Encryptor/Decryptor")
    
    frame = tk.Frame(root)
    frame.pack(pady=20, padx=20)
    
    key_length_var = tk.IntVar(value=16)  # Default to 128-bit (16 bytes)
    
    def set_key_length():
        selection = key_length_var.get()
        if selection == 16:
            key_length = 16
        elif selection == 24:
            key_length = 24
        elif selection == 32:
            key_length = 32
        return key_length
    
    tk.Label(frame, text="Select AES Key Length:").pack(anchor=tk.W)
    
    tk.Radiobutton(frame, text="128-bit (16 bytes)", variable=key_length_var, value=16).pack(anchor=tk.W)
    tk.Radiobutton(frame, text="192-bit (24 bytes)", variable=key_length_var, value=24).pack(anchor=tk.W)
    tk.Radiobutton(frame, text="256-bit (32 bytes)", variable=key_length_var, value=32).pack(anchor=tk.W)
    
    result_label = tk.Label(frame, text="", fg="blue")
    result_label.pack(pady=10)
    
    encrypt_button = tk.Button(frame, text="Encrypt File", command=lambda: process_file("encrypt", set_key_length(), result_label))
    encrypt_button.pack(side=tk.LEFT, padx=10)
    
    decrypt_button = tk.Button(frame, text="Decrypt File", command=lambda: process_file("decrypt", set_key_length(), result_label))
    decrypt_button.pack(side=tk.LEFT, padx=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
