# Mengimpor library
import os # Digunakan untuk menghasilkan vektor inisialisasi (IV) acak
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Digunakan untuk implementasi AES dan padding.
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk # Digunakan untuk membuat antarmuka pengguna grafis (GUI).
from tkinter import filedialog, simpledialog, messagebox # Komponen dari tkinter untuk memilih file, memasukkan kunci, dan menampilkan pesan.

class AESFileEncryptor:
    # Inisialisasi objek dengan kunci yang diubah menjadi byte dan backend default dari cryptography
    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.backend = default_backend()
    
    # Menambahkan padding ke data agar sesuai dengan ukuran blok AES.
    def _pad_data(self, data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data
    
    # Menghapus padding dari data yang telah diproses.
    def _unpad_data(self, data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    
    # Mengenkripsi data menggunakan AES dalam mode CBC dengan IV acak.
    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padded_plaintext = self._pad_data(plaintext)
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext
    
    # Mendekripsi data yang telah dienkripsi, mengembalikan plaintext yang asli.
    def decrypt(self, ciphertext):
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        plaintext = self._unpad_data(padded_plaintext)
        return plaintext

# Membuka dialog untuk memilih file yang akan dienkripsi atau didekripsi.
def select_file():
    file_path = filedialog.askopenfilename()
    return file_path

# Meminta pengguna untuk memasukkan kunci enkripsi dengan panjang yang valid (16, 24, atau 32 byte).
def get_key():
    key = simpledialog.askstring("Input", "Enter the encryption key (must be 16, 24, or 32 bytes):")
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Error", "Invalid key length. Key must be 16, 24, or 32 bytes long.")
        return None
    return key

# Mengelola seluruh proses enkripsi atau deskripsi file, termasuk pemilihan file, pembacaan data, pemrosesan data, dan penyimpanan hasilnya.
def process_file(operation):
    file_path = select_file()
    if not file_path:
        return
    
    key = get_key()
    if not key:
        return
    
    encryptor = AESFileEncryptor(key)
    
    with open(file_path, 'rb') as file:
        data = file.read()
    
    if operation == "encrypt":
        processed_data = encryptor.encrypt(data)
    elif operation == "decrypt":
        processed_data = encryptor.decrypt(data)
    else:
        raise ValueError("Invalid operation")
    
    output_file_path = filedialog.asksaveasfilename()
    if output_file_path:
        with open(output_file_path, 'wb') as file:
            file.write(processed_data)
        messagebox.showinfo("Success", f"File has been {operation}ed and saved successfully.")

# Membuat antarmuka pengguna dengan dua tombol untuk memilih operasi enkripsi atau deskripsi.
def create_gui():
    root = tk.Tk()
    root.title("AES File Encryptor/Decryptor")
    
    frame = tk.Frame(root)
    frame.pack(pady=20, padx=20)
    
    encrypt_button = tk.Button(frame, text="Encrypt File", command=lambda: process_file("encrypt"))
    encrypt_button.pack(side=tk.LEFT, padx=10)
    
    decrypt_button = tk.Button(frame, text="Decrypt File", command=lambda: process_file("decrypt"))
    decrypt_button.pack(side=tk.LEFT, padx=10)
    
    root.mainloop()

# Menjalankan fungsi create_gui jika script dijalankan sebagai program utama.
if __name__ == "__main__":
    create_gui()