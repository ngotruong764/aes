from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# Function to encrypt using AES in CBC mode
def encrypt_AES_CBC(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8'))
    padded_data += padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


# Function to decrypt using AES in CBC mode
def decrypt_AES_CBC(ciphertext, key, iv):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data)
    unpadded_data += unpadder.finalize()

    return unpadded_data.decode('utf-8')


# Example usage
key = b'MySuperSecretKey2222222222222222'  # Encryption key (Ensure the key is 16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
iv = b'MySuperSecretIV0'  # Initialization vector (Ensure the IV is 16 bytes)
plaintext = "This is my secret text"
# Encrypt the plaintext
encrypted_text = encrypt_AES_CBC(plaintext, key, iv)
print(f'Encrypted text: {encrypted_text}')

# Decrypt the encrypted text
decrypted_text = decrypt_AES_CBC(encrypted_text, key, iv)
print(f'Decrypted text: {decrypted_text}')
