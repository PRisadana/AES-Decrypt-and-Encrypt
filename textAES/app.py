from tkinter import Tk, Label, Entry, Button, messagebox # untuk membuat UI
from Crypto.Cipher import AES #library AES
from Crypto.Random import get_random_bytes #untuk menghasilkan bilangan acak
import base64
import hashlib

# Menambahkan padding ke data
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + (chr(pad_len) * pad_len).encode()

# menghapus padding setelah dekripsi
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Fungsi untuk melakukan enkripsi
def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode()))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

# Fungsi untuk melakukan deskripsi
def decrypt(cipher_text, key):
    iv = base64.b64decode(cipher_text[:24])
    ct = base64.b64decode(cipher_text[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    return pt.decode('utf-8')

# Menghasilkan hash SHA-256 dari teks dan mengambil 16 byte pertama
def get_aes_key_from_text(text): 
    return hashlib.sha256(text.encode()).digest()[:16]

# dipanggil saat pengguna mengklik tombol "Encrypt"
# membaca teks dan kunci dari bidang masukan, melakukan enkripsi,
# dan menampilkan hasilnya di bidang masukan yang sesuai
def perform_encryption():
    plain_text = plaintext_entry.get()
    key_text = key_entry.get()
    if not plain_text or not key_text:
        messagebox.showerror("Error", "Please enter both plaintext and key.")
        return
    key = get_aes_key_from_text(key_text)
    cipher_text = encrypt(plain_text, key)
    ciphertext_entry.delete(0, 'end')
    ciphertext_entry.insert(0, cipher_text)

# dipanggil saat pengguna mengklik tombol "Decrypt"
# membaca teks dan kunci dari bidang masukan, melakukan deskripsi,
# dan menampilkan hasilnya di bidang masukan yang sesuai
def perform_decryption():
    cipher_text = ciphertext_entry.get()
    key_text = key_entry.get()
    if not cipher_text or not key_text:
        messagebox.showerror("Error", "Please enter both ciphertext and key.")
        return
    key = get_aes_key_from_text(key_text)
    decrypted_text = decrypt(cipher_text, key)
    decryptedtext_entry.delete(0, 'end')
    decryptedtext_entry.insert(0, decrypted_text)

# Setup UI
root = Tk()
root.title("AES Text Encryption/Decryption")

# Labels
Label(root, text="Plaintext:").grid(row=0, column=0, padx=10, pady=10)
Label(root, text="Ciphertext:").grid(row=1, column=0, padx=10, pady=10)
Label(root, text="Key:").grid(row=2, column=0, padx=10, pady=10)
Label(root, text="Decrypted Text:").grid(row=3, column=0, padx=10, pady=10)

# Entries
plaintext_entry = Entry(root)
plaintext_entry.grid(row=0, column=1, padx=10, pady=10)
ciphertext_entry = Entry(root)
ciphertext_entry.grid(row=1, column=1, padx=10, pady=10)
key_entry = Entry(root)
key_entry.grid(row=2, column=1, padx=10, pady=10)
decryptedtext_entry = Entry(root)
decryptedtext_entry.grid(row=3, column=1, padx=10, pady=10)

# Buttons
Button(root, text="Encrypt", command=perform_encryption).grid(row=4, column=0, padx=10, pady=10)
Button(root, text="Decrypt", command=perform_decryption).grid(row=4, column=1, padx=10, pady=10)

root.mainloop()
