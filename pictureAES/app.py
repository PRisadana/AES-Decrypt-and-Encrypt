from tkinter import Tk, Label, Entry, Button, filedialog, messagebox, StringVar
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time

# Fungsi untuk memuat gambar dari file
def load_image(image_path):
    return Image.open(image_path)

# Fungsi untuk menyimpan gambar ke file
def save_image(image, path):
    image.save(path)

# Fungsi untuk mengkonversi gambar menjadi byte array
def image_to_bytes(image):
    return image.tobytes()

# Fungsi untuk mengkonversi byte array kembali menjadi gambar
def bytes_to_image(byte_data, size):
    return Image.frombytes('RGB', size, byte_data)

# Fungsi untuk mengenkripsi data menggunakan AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)  # Membuat objek cipher dengan mode CBC
    ciphertext = cipher.encrypt(pad(data, AES.block_size))  # Enkripsi data dan pad jika perlu
    return cipher.iv + ciphertext  # Gabungkan IV dan ciphertext

# Fungsi untuk mendekripsi data menggunakan AES
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]  # Ekstrak IV dari data terenkripsi
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Membuat objek cipher dengan IV yang sama
    ciphertext = encrypted_data[AES.block_size:]  # Ekstrak ciphertext dari data terenkripsi
    return unpad(cipher.decrypt(ciphertext), AES.block_size)  # Dekripsi dan unpad data

# Fungsi untuk mengenkripsi gambar dan menyimpan hasilnya
def encrypt_image(image_path, key, output_path):
    print("Loading image for encryption...")
    image = load_image(image_path)  # Memuat gambar dari file
    image_bytes = image_to_bytes(image)  # Konversi gambar menjadi byte array
    print("Encrypting image data...")
    encrypted_data = encrypt_data(image_bytes, key)  # Enkripsi data gambar
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)  # Simpan data terenkripsi ke file
    # Simpan ukuran gambar di file terpisah
    with open(output_path + '.size', 'wb') as f:
        width, height = image.size
        f.write(width.to_bytes(4, 'big'))
        f.write(height.to_bytes(4, 'big'))
    print(f"Encrypted image saved to: {output_path}")
    return image

# Fungsi untuk mendekripsi gambar dan menyimpan hasilnya
def decrypt_image(encrypted_path, key, output_path):
    print("Reading encrypted image data...")
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()  # Baca data terenkripsi dari file
    print("Decrypting image data...")
    decrypted_data = decrypt_data(encrypted_data, key)  # Dekripsi data gambar
    # Membaca ukuran gambar dari file .size
    with open(encrypted_path + '.size', 'rb') as f:
        size_bytes = f.read(8)
        width, height = int.from_bytes(size_bytes[:4], 'big'), int.from_bytes(size_bytes[4:], 'big')
    decrypted_image = bytes_to_image(decrypted_data, (width, height))  # Konversi byte array kembali menjadi gambar
    save_image(decrypted_image, output_path)  # Simpan gambar yang telah didekripsi ke file
    print(f"Decrypted image saved to: {output_path}")
    return decrypted_image

# Fungsi untuk memilih file gambar untuk dienkripsi
def select_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if file_path:
        image_path.set(file_path)  # Set jalur file gambar yang dipilih
        display_image(file_path, original_image_label)  # Tampilkan gambar asli di GUI

# Fungsi untuk memilih file terenkripsi untuk didekripsi
def select_encrypted_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.aes")])
    if file_path:
        encrypted_path.set(file_path)  # Set jalur file terenkripsi yang dipilih
        display_image(file_path, encrypted_image_label)  # Tampilkan gambar terenkripsi di GUI (placeholder)

# Fungsi untuk melakukan enkripsi gambar yang dipilih
def perform_encryption():
    if not image_path.get() or not key_entry.get():
        messagebox.showerror("Error", "Please select an image and enter a key.")  # Tampilkan pesan error jika gambar atau kunci tidak dipilih
        return

    key = key_entry.get().encode('utf-8')
    key = key.ljust(16)[:16]  # Pastikan panjang kunci adalah 16 byte (AES-128)
    output_path = filedialog.asksaveasfilename(defaultextension=".aes", filetypes=[("Encrypted Files", "*.aes")])
    if output_path:
        image = load_image(image_path.get())  # Memuat gambar asli
        start_time = time.time()  # Mulai timer
        try:
            encrypt_image(image_path.get(), key, output_path)  # Lakukan enkripsi
            encryption_time = time.time() - start_time  # Hitung waktu enkripsi
            encryption_time_label.config(text=f"Encryption Time: {encryption_time:.2f} seconds")  # Tampilkan waktu enkripsi di GUI
            display_image(image_path.get(), original_image_label)  # Tampilkan gambar asli di GUI
            display_image(output_path, encrypted_image_label)  # Tampilkan gambar terenkripsi di GUI (placeholder)
            messagebox.showinfo("Success", f"File has been encrypted and saved successfully.")  # Tampilkan pesan sukses
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")  # Tampilkan pesan error jika gagal

# Fungsi untuk melakukan dekripsi gambar yang dipilih
def perform_decryption():
    if not encrypted_path.get() or not key_entry.get():
        messagebox.showerror("Error", "Please select an encrypted file and enter a key.")  # Tampilkan pesan error jika file terenkripsi atau kunci tidak dipilih
        return

    key = key_entry.get().encode('utf-8')
    key = key.ljust(16)[:16]  # Pastikan panjang kunci adalah 16 byte (AES-128)
    output_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG Files", "*.jpg")])
    if output_path:
        start_time = time.time()  # Mulai timer
        try:
            decrypted_image = decrypt_image(encrypted_path.get(), key, output_path)  # Lakukan dekripsi
            decryption_time = time.time() - start_time  # Hitung waktu dekripsi
            decryption_time_label.config(text=f"Decryption Time: {decryption_time:.2f} seconds")  # Tampilkan waktu dekripsi di GUI
            display_image(output_path, decrypted_image_label)  # Tampilkan gambar hasil dekripsi di GUI
            messagebox.showinfo("Success", f"File has been decrypted and saved successfully.")  # Tampilkan pesan sukses
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")  # Tampilkan pesan error jika gagal

# Fungsi untuk menampilkan gambar di label GUI
def display_image(image_path, label):
    if image_path.endswith(".aes"):
        image = Image.new("RGB", (250, 250), "gray")  # Jika file adalah .aes, tampilkan gambar placeholder abu-abu
    else:
        image = Image.open(image_path)  # Memuat gambar dari file
    image.thumbnail((250, 250))  # Resize gambar agar muat di label
    photo = ImageTk.PhotoImage(image)  # Konversi gambar ke format yang bisa ditampilkan di Tkinter
    label.config(image=photo)  # Set gambar di label
    label.image = photo  # Simpan referensi ke gambar untuk mencegah garbage collection

# Setup UI
root = Tk()
root.title("Image Encryption/Decryption")

image_path = StringVar()
encrypted_path = StringVar()

# Label dan tombol untuk memilih file gambar
Label(root, text="Select Image for Encryption:").grid(row=0, column=0, padx=10, pady=10)
Button(root, text="Browse", command=select_image).grid(row=0, column=1, padx=10, pady=10)

# Label dan tombol untuk memilih file terenkripsi
Label(root, text="Select Encrypted File for Decryption:").grid(row=1, column=0, padx=10, pady=10)
Button(root, text="Browse", command=select_encrypted_file).grid(row=1, column=1, padx=10, pady=10)

# Label dan entry untuk memasukkan kunci enkripsi/dekripsi
Label(root, text="Enter Key:").grid(row=2, column=0, padx=10, pady=10)
key_entry = Entry(root, show="*")
key_entry.grid(row=2, column=1, padx=10, pady=10)

# Tombol untuk melakukan enkripsi dan dekripsi
Button(root, text="Encrypt Image", command=perform_encryption).grid(row=3, column=0, padx=10, pady=10)
Button(root, text="Decrypt Image", command=perform_decryption).grid(row=3, column=1, padx=10, pady=10)

# Label untuk menampilkan gambar asli
original_image_label = Label(root)
original_image_label.grid(row=4, column=0, padx=10, pady=10)

# Label untuk menampilkan gambar terenkripsi
encrypted_image_label = Label(root)
encrypted_image_label.grid(row=4, column=1, padx=10, pady=10)

# Label untuk menampilkan gambar hasil dekripsi
decrypted_image_label = Label(root)
decrypted_image_label.grid(row=4, column=2, padx=10, pady=10)

# Label untuk menampilkan waktu enkripsi
encryption_time_label = Label(root, text="Encryption Time: 0.00 seconds")
encryption_time_label.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# Label untuk menampilkan waktu dekripsi
decryption_time_label = Label(root, text="Decryption Time: 0.00 seconds")
decryption_time_label.grid(row=5, column=1, columnspan=2, padx=10, pady=10)

root.mainloop()
