# Text, Images, and File Cryptography Using Advanced Encryption Standard (AES)

Project ini mengimplementasikan teknik kriptografi untuk mengenkripsi dan mendekripsi teks, gambar, dan file menggunakan algoritma AES (Advanced Encryption Standard) dengan mode CBC (Cipher Block Chaining). Program ini dibangun menggunakan Python dengan bantuan beberapa library seperti tkinter untuk antarmuka pengguna dan PIL (Pillow) untuk pemrosesan gambar.

## Our Team

```
+-----------------------------------+------------+
| Gede Reva Prasetya Paramarta      | 2205551015 |
| Resandy Prisadana                 | 2205551050 |
| I Nyoman Danu Daksawan Randysmara	| 2205551062 |
| I Gede Teja Baskara               | 2205551065 |
| I Putu Eka Putra Juniawan         | 2205551087 |
+-----------------------------------+------------+
```

## Main Feature

- Enkripsi dan dekripsi teks menggunakan AES-128.
- Enkripsi dan dekripsi gambar dengan menyimpan metadata (ukuran gambar) terpisah.
- Enkripsi dan dekripsi file dengan menggunakan AES dengan berbagai panjang kunci (128-bit, 192-bit, 256-bit).

## Installation

1. Pastikan Python 3.x sudah terinstal.

2. Install dependencies dengan menjalankan perintah berikut:

```
pip install Pillow cryptography
```

## How To Use

### Enkripsi Teks

- Masukkan teks yang akan dienkripsi.
- Masukkan kunci enkripsi (harus berupa 16 karakter).
- Klik tombol "Encrypt".
- Teks terenkripsi akan ditampilkan di area yang sesuai.

#### Dekripsi Teks

- Masukkan teks terenkripsi.
- Masukkan kunci enkripsi yang sama yang digunakan untuk enkripsi.
- Klik tombol "Decrypt".
- Teks asli akan ditampilkan di area yang sesuai.

#### Enkripsi Gambar

- Pilih gambar yang akan dienkripsi.
- Masukkan kunci enkripsi (harus berupa 16 karakter).
- Klik tombol "Encrypt Image".
- Gambar terenkripsi akan ditampilkan dan disimpan sebagai file .aes.

### Dekripsi Gambar

- Pilih file gambar terenkripsi (format .aes).
- Masukkan kunci enkripsi yang sama yang digunakan untuk enkripsi.
- Klik tombol "Decrypt Image".
- Gambar yang telah didekripsi akan ditampilkan dan disimpan sebagai file gambar.

#### Enkripsi File

- Pilih file yang akan dienkripsi.
- Masukkan kunci enkripsi (16, 24, atau 32 byte).
- Klik tombol "Encrypt File".
- File terenkripsi akan disimpan dengan ekstensi .aes.

#### Dekripsi File

- Pilih file terenkripsi (format .aes).
- Masukkan kunci enkripsi yang sama yang digunakan untuk enkripsi.
- Klik tombol "Decrypt File".
- File yang telah didekripsi akan disimpan dengan ekstensi yang sesuai.
