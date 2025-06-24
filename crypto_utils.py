from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_keys(save_dir="."):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key_path = os.path.join(save_dir, "private_key.pem")
    public_key_path = os.path.join(save_dir, "public_key.pem")

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key_path, public_key_path


import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_file(file_path, public_key_path="public_key.pem"):
    with open(file_path, "rb") as f:
        data = f.read()

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    aes_key = secrets.token_bytes(32)
    
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

   
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

  
    len_key = len(encrypted_aes_key).to_bytes(2, byteorder='big')
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(len_key)
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(encrypted_data)

    return encrypted_path


def decrypt_file(file_path, private_key_path="private_key.pem"):
    with open(file_path, "rb") as f:
        
        len_key_bytes = f.read(2)
        len_key = int.from_bytes(len_key_bytes, byteorder='big')

        encrypted_aes_key = f.read(len_key)

        iv = f.read(16)

        encrypted_data = f.read()

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    decrypted_file_path = file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, "wb") as f:
        f.write(data)

    return decrypted_file_path

