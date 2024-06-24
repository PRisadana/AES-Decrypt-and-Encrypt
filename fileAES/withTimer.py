# Mengimpor Libarry yang diperlukan
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk

# Konstruktor kelas, menginisialisasi objek AESFileEncryptor dengan kunci enkripsi dan backend default.
class AESFileEncryptor:
    def __init__(self, key):
        self.key = key
        self.backend = default_backend()
    
    # Fungsi untuk menambahkan padding pada data sehingga panjangnya menjadi kelipatan 16 byte (ukuran blok AES).
    # Padding ini menggunakan standar PKCS7.
    def _pad_data(self, data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data
    
    # Fungsi untuk menghapus padding dari data yang telah didekripsi sehingga kembali ke ukuran aslinya.
    def _unpad_data(self, data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    
    # Fungsi untuk mengenkripsi data
    def encrypt(self, plaintext):
        iv = os.urandom(16) # Menghasilkan vektor inisialisasi (IV) acak sepanjang 16 byte.
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend) # Membuat objek cipher AES dalam mode CBC dengan kunci dan IV yang dihasilkan.
        encryptor = cipher.encryptor()
        padded_plaintext = self._pad_data(plaintext) # Mengenkripsi data yang telah dipadding dan menggabungkan IV dengan ciphertext sebagai hasil akhir.
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        # Menampilkan ciphertext dalam terminal
        print(f"Ciphertext: {ciphertext.hex()}")
        return iv + ciphertext
    
    # Fungsi untuk mendekripsi data.
    def decrypt(self, ciphertext):
        iv = ciphertext[:16] # Memisahkan IV dari ciphertext.
        actual_ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend) # Membuat objek cipher AES dalam mode CBC dengan kunci dan IV yang dipisahkan.
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        plaintext = self._unpad_data(padded_plaintext) # Mendekripsi ciphertext dan menghapus padding dari hasil dekripsi.
        # # Menampilkan plaintext dalam terminal
        # print(f"Plaintext: {plaintext.decode('utf-8', errors='ignore')}")
        return plaintext

# Menggunakan dialog file untuk memungkinkan pengguna memilih file dan mengembalikan jalur file yang dipilih.
def select_file():
    file_path = filedialog.askopenfilename()
    return file_path

# Mengambil kunci enkripsi dari pengguna melalui dialog input
def get_key(key_length):
    key = simpledialog.askstring("Input", f"Enter the encryption key (must be {key_length} bytes):")
    if len(key) != key_length: # Memverifikasi panjang kunci sesuai dengan panjang yang diperlukan.
        messagebox.showerror("Error", f"Invalid key length. Key must be {key_length} bytes long.")
        return None
    return key.encode('utf-8') # Mengembalikan kunci dalam bentuk byte.

# Fungsi utama untuk memproses enkripsi atau dekripsi file
def process_file(operation, key_length, result_label):
    file_path = select_file() # Memilih file
    if not file_path:
        return
    
    key = get_key(key_length) # mengambil kunci enkripsi.
    if not key:
        return
    
    encryptor = AESFileEncryptor(key) # Membuat objek AESFileEncryptor dengan kunci.
    
    with open(file_path, 'rb') as file: # Membaca data dari file yang dipilih.
        data = file.read()
    
    start_time = time.time() # Menghitung waktu yang dibutuhkan untuk proses enkripsi atau dekripsi.
    if operation == "encrypt":
        processed_data = encryptor.encrypt(data)
    elif operation == "decrypt":
        processed_data = encryptor.decrypt(data)
    else:
        raise ValueError("Invalid operation")
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    
    output_file_path = filedialog.asksaveasfilename() # Menyimpan hasil enkripsi atau dekripsi ke file baru.
    if output_file_path:
        with open(output_file_path, 'wb') as file:
            file.write(processed_data)
        messagebox.showinfo("Success", f"File has been {operation}ed and saved successfully.")
    
    result_label.config(text=f"Time taken for {operation}: {elapsed_time:.6f} seconds") # Menampilkan waktu yang dibutuhkan untuk proses di GUI.

# Membuat antarmuka pengguna untuk program
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
    
    # Menambahkan radio button untuk memilih panjang kunci AES (128-bit, 192-bit, 256-bit).
    tk.Radiobutton(frame, text="128-bit (16 bytes)", variable=key_length_var, value=16).pack(anchor=tk.W)
    tk.Radiobutton(frame, text="192-bit (24 bytes)", variable=key_length_var, value=24).pack(anchor=tk.W)
    tk.Radiobutton(frame, text="256-bit (32 bytes)", variable=key_length_var, value=32).pack(anchor=tk.W)
    
    result_label = tk.Label(frame, text="", fg="blue")
    result_label.pack(pady=10)
    
    # Menambahkan tombol untuk memproses enkripsi dan dekripsi file.
    encrypt_button = tk.Button(frame, text="Encrypt File", command=lambda: process_file("encrypt", set_key_length(), result_label))
    encrypt_button.pack(side=tk.LEFT, padx=10)
    
    decrypt_button = tk.Button(frame, text="Decrypt File", command=lambda: process_file("decrypt", set_key_length(), result_label))
    decrypt_button.pack(side=tk.LEFT, padx=10)
    
    root.mainloop()

# Memulai GUI ketika skrip dijalankan.
if __name__ == "__main__":
    create_gui()
