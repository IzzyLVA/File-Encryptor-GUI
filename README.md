# 🔐 File Encryptor GUI

This is a Python desktop application that provides an easy-to-use interface for encrypting and decrypting files using a hybrid cryptographic approach (RSA + AES). It’s built using `tkinter` for the GUI and the `cryptography` library for secure encryption.

---

## 🚀 Features

- ✅ RSA Key Pair Generation (2048-bit)
- ✅ AES-256 File Encryption using RSA-encrypted keys
- ✅ Secure File Decryption
- ✅ Simple, responsive GUI built with `tkinter`
- ✅ Automatic file handling and secure key storage

---

## 📦 Requirements

- Python 3.6+
- `cryptography` library

You can install the required package using pip:

```bash
pip install cryptography
```

---

## 🛠 How It Works

- **Key Generation**: Generates a 2048-bit RSA public/private key pair and saves them as PEM files.
- **Encryption**: 
  - Encrypts your file using a random AES-256 key.
  - The AES key is encrypted using the RSA public key.
  - The resulting `.enc` file includes the RSA-encrypted key, the AES IV, and the encrypted content.
- **Decryption**: 
  - Extracts the AES key by decrypting it with the RSA private key.
  - Decrypts the file content using AES-CBC mode.

---

## 🖥️ How to Use

1. Run the app:

   ```bash
   python app.py
   ```

2. Click `Generate Keys` to create a new RSA key pair.

3. Use `Encrypt File` to select a file to encrypt.
   - Output: `[filename].enc`

4. Use `Decrypt File` to select an encrypted file to decrypt.
   - Output: `[filename].dec`

> **Note**: Encrypted and decrypted files are saved in the same directory as the original file.

---

## 📁 Project Structure

```
.
├── app.py               # GUI and main app logic
├── crypto_utils.py      # Encryption, decryption, and key handling logic
├── private_key.pem      # RSA Private Key (generated at runtime)
├── public_key.pem       # RSA Public Key (generated at runtime)
```

---

## 🔒 Security Notes

- The AES key is randomly generated per file, ensuring strong encryption.
- The private RSA key is stored unencrypted; for real-world applications, consider password-protecting or securely storing it.
- RSA-OAEP with SHA-256 is used for secure key exchange.

---

## 📜 License

This project is open-source under the MIT License. You are free to use, modify, and distribute it.

