from tkinter import Tk, Label, Entry, Button, messagebox # untuk membuat UI
from Crypto.Cipher import AES #library AES untuk enkripsi dan dekripsi
from Crypto.Random import get_random_bytes #untuk menghasilkan bilangan acak
import base64
import hashlib

# Menambahkan padding ke data agar sesuai dengan ukuran blok AES (16 byte)
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + (chr(pad_len) * pad_len).encode()

# Menghapus padding setelah dekripsi untuk mendapatkan data asli
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Fungsi untuk melakukan enkripsi teks menggunakan AES
def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC) # Membuat objek cipher dengan mode CBC
    ct_bytes = cipher.encrypt(pad(plain_text.encode())) # Enkripsi teks setelah menambahkan padding
    iv = base64.b64encode(cipher.iv).decode('utf-8') # Mengkodekan IV menjadi Base64
    ct = base64.b64encode(ct_bytes).decode('utf-8') # Mengkodekan ciphertext menjadi Base64
    return iv + ct # Menggabungkan IV dan ciphertext

# Fungsi untuk melakukan dekripsi teks menggunakan AES
def decrypt(cipher_text, key):
    iv = base64.b64decode(cipher_text[:24]) # Mendekode IV dari Base64
    ct = base64.b64decode(cipher_text[24:]) # Mendekode ciphertext dari Base64
    cipher = AES.new(key, AES.MODE_CBC, iv) # Membuat objek cipher dengan IV yang sama
    pt = unpad(cipher.decrypt(ct)) # Mendekripsi dan menghapus padding
    return pt.decode('utf-8') # Mengembalikan teks asli

# Menghasilkan hash SHA-256 dari teks dan mengambil 16 byte pertama sebagai kunci AES
def get_aes_key_from_text(text): 
    return hashlib.sha256(text.encode()).digest()[:16]

# Dipanggil saat pengguna mengklik tombol "Encrypt"
# Membaca teks dan kunci dari bidang masukan, melakukan enkripsi,
# dan menampilkan hasilnya di bidang masukan yang sesuai
def perform_encryption():
    plain_text = plaintext_entry.get() # Membaca teks asli dari input pengguna
    key_text = key_entry.get() # Membaca kunci dari input pengguna
    if not plain_text or not key_text: # Validasi input
        messagebox.showerror("Error", "Please enter both plaintext and key.")
        return
    key = get_aes_key_from_text(key_text) # Menghasilkan kunci AES dari teks kunci
    cipher_text = encrypt(plain_text, key) # Melakukan enkripsi
    ciphertext_entry.delete(0, 'end') # Menghapus teks di bidang input ciphertext
    ciphertext_entry.insert(0, cipher_text) # Menampilkan ciphertext di bidang input

# Dipanggil saat pengguna mengklik tombol "Decrypt"
# Membaca teks dan kunci dari bidang masukan, melakukan deskripsi,
# dan menampilkan hasilnya di bidang masukan yang sesuai
def perform_decryption():
    cipher_text = ciphertext_entry.get() # Membaca ciphertext dari input pengguna
    key_text = key_entry.get() # Membaca kunci dari input pengguna
    if not cipher_text or not key_text: # Validasi input
        messagebox.showerror("Error", "Please enter both ciphertext and key.")
        return
    key = get_aes_key_from_text(key_text) # Menghasilkan kunci AES dari teks kunci
    decrypted_text = decrypt(cipher_text, key) # Melakukan dekripsi
    decryptedtext_entry.delete(0, 'end') # Menghapus teks di bidang input decrypted text
    decryptedtext_entry.insert(0, decrypted_text) # Menampilkan teks asli di bidang input

# Setup UI menggunakan Tkinter
root = Tk()
root.title("AES Text Encryption/Decryption")

# Labels untuk menunjukkan input yang diperlukan
Label(root, text="Plaintext:").grid(row=0, column=0, padx=10, pady=10)
Label(root, text="Ciphertext:").grid(row=1, column=0, padx=10, pady=10)
Label(root, text="Key:").grid(row=2, column=0, padx=10, pady=10)
Label(root, text="Decrypted Text:").grid(row=3, column=0, padx=10, pady=10)

# Entries untuk menerima input dari pengguna
plaintext_entry = Entry(root, width=100)
plaintext_entry.grid(row=0, column=1, padx=10, pady=10)
ciphertext_entry = Entry(root, width=100)
ciphertext_entry.grid(row=1, column=1, padx=10, pady=10)
key_entry = Entry(root, width=100)
key_entry.grid(row=2, column=1, padx=10, pady=10)
decryptedtext_entry = Entry(root, width=100)
decryptedtext_entry.grid(row=3, column=1, padx=10, pady=10)

# Buttons untuk memicu enkripsi dan dekripsi
Button(root, width=50, text="Encrypt", command=perform_encryption).grid(row=4, column=0, padx=10, pady=10)
Button(root, width=50, text="Decrypt", command=perform_decryption).grid(row=4, column=1, padx=10, pady=10)

# Menjalankan aplikasi Tkinter
root.mainloop()
