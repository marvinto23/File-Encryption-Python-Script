import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(file_name, password):
    # Generate a salt
    salt = os.urandom(16)
    # Generate key from password using the salt and KDF
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password)
    # Encrypt the file
    with open(file_name, "rb") as file:
        plaintext = file.read()
    cipher = Cipher(algorithms.XChaCha20Poly1305(key), modes.GCM(os.urandom(12)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # write the metadata to a json file
    metadata = {
        'original_name': file_name,
        'salt': salt,
        'nonce': encryptor.nonce,
        'ciphertext': ciphertext,
        'tag': encryptor.tag
    }
    encrypted_file_metadata = file_name + ".metadata"
    with open(encrypted_file_metadata, "wb") as f:
        f.write(json.dumps(metadata))
    os.remove(file_name)
    return encrypted_file_metadata

def decrypt_file(file_metadata, password):
    # read the metadata from json file
    with open(file_metadata, "rb") as f:
        metadata = json.loads(f.read())
    # Generate key from password using the salt and KDF
    salt = metadata['salt']
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password)
    # Decrypt the file
    cipher = Cipher(algorithms.XChaCha20Poly1305(key), modes.GCM(metadata['nonce'], metadata['tag']), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(metadata['ciphertext']) + decryptor.finalize()
    decrypted_file = metadata['original_name']
    with open(decrypted_file, "wb") as file:
        file.write(plaintext)
    os.remove(file_metadata)
    return decrypted
