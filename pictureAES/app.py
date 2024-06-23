from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, StringVar
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Fungsi untuk memuat gambar
def load_image(image_path):
    return Image.open(image_path)

# Fungsi untuk menyimpan gambar
def save_image(image, path):
    image.save(path)

# Fungsi untuk mengkonversi gambar menjadi byte array
def image_to_bytes(image):
    return image.tobytes()

# Fungsi untuk mengkonversi byte array kembali menjadi gambar
def bytes_to_image(byte_data, size):
    return Image.frombytes('RGB', size, byte_data)

# Fungsi untuk mengenkripsi data
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ciphertext

# Fungsi untuk mendekripsi data
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = encrypted_data[AES.block_size:]
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# Fungsi untuk mengenkripsi gambar
def encrypt_image(image_path, key, output_path):
    print("Loading image for encryption...")
    image = load_image(image_path)
    image_bytes = image_to_bytes(image)
    print("Encrypting image data...")
    encrypted_data = encrypt_data(image_bytes, key)
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    print(f"Encrypted image saved to: {output_path}")

# Fungsi untuk mendekripsi gambar
def decrypt_image(encrypted_path, key, output_path):
    print("Reading encrypted image data...")
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    print("Decrypting image data...")
    decrypted_data = decrypt_data(encrypted_data, key)
    # Mendapatkan ukuran gambar dari file asli sebelum enkripsi
    with open(encrypted_path, 'rb') as f:
        f.seek(-8, os.SEEK_END)
        size_bytes = f.read(8)
        width, height = int.from_bytes(size_bytes[:4], 'big'), int.from_bytes(size_bytes[4:], 'big')
    decrypted_image = bytes_to_image(decrypted_data, (width, height))
    save_image(decrypted_image, output_path)
    print(f"Decrypted image saved to: {output_path}")

def select_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if file_path:
        image_path.set(file_path)

def select_encrypted_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.aes")])
    if file_path:
        encrypted_path.set(file_path)

def perform_encryption():
    if not image_path.get() or not key_entry.get():
        messagebox.showerror("Error", "Please select an image and enter a key.")
        return

    key = key_entry.get().encode('utf-8')
    key = key.ljust(16)[:16]  # Ensure the key is exactly 16 bytes (AES-128)
    output_path = filedialog.asksaveasfilename(defaultextension=".aes", filetypes=[("Encrypted Files", "*.aes")])
    if output_path:
        image = load_image(image_path.get())
        width, height = image.size
        encrypt_image(image_path.get(), key, output_path)
        # Simpan ukuran gambar di akhir file terenkripsi
        with open(output_path, 'ab') as f:
            f.write(width.to_bytes(4, 'big'))
            f.write(height.to_bytes(4, 'big'))

def perform_decryption():
    if not encrypted_path.get() or not key_entry.get():
        messagebox.showerror("Error", "Please select an encrypted file and enter a key.")
        return

    key = key_entry.get().encode('utf-8')
    key = key.ljust(16)[:16]  # Ensure the key is exactly 16 bytes (AES-128)
    output_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG Files", "*.jpg")])
    if output_path:
        decrypt_image(encrypted_path.get(), key, output_path)

# Setup UI
root = Tk()
root.title("Image Encryption/Decryption")

image_path = StringVar()
encrypted_path = StringVar()

Label(root, text="Select Image for Encryption:").grid(row=0, column=0, padx=10, pady=10)
Button(root, text="Browse", command=select_image).grid(row=0, column=1, padx=10, pady=10)

Label(root, text="Select Encrypted File for Decryption:").grid(row=1, column=0, padx=10, pady=10)
Button(root, text="Browse", command=select_encrypted_file).grid(row=1, column=1, padx=10, pady=10)

Label(root, text="Enter Key:").grid(row=2, column=0, padx=10, pady=10)
key_entry = Entry(root, show="*")
key_entry.grid(row=2, column=1, padx=10, pady=10)

Button(root, text="Encrypt Image", command=perform_encryption).grid(row=3, column=0, padx=10, pady=10)
Button(root, text="Decrypt Image", command=perform_decryption).grid(row=3, column=1, padx=10, pady=10)

root.mainloop()
