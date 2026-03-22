# encryption.py - AES-256 GCM encrypt/decrypt
# encryption.py - AES-256 GCM Encryption & Decryption
# Used by both sender (to encrypt) and receiver (to decrypt)

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
     
    nonce = os.urandom(12)

    # Create an AESGCM cipher object using our 32-byte key
    aesgcm = AESGCM(key)

    # Encrypt the data
    # The None argument is for "associated data" (we are not using it here)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
  
    aesgcm = AESGCM(key)

    # Decrypt — GCM automatically verifies integrity here
    # If anything was tampered with, this line will raise an exception
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext