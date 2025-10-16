from getpass import getpass
from argon2.low_level import hash_secret_raw, Type
import os
from storage import init_db, vault_exists, get_vault_salt, set_vault_salt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, AESGCM
from cryptography.hazmat.backends import default_backend

def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte master key from a password and salt using Argon2id.
    """
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=102400,  # ~100 MB
        parallelism=8,
        hash_len=32,         # AES-256 key
        type=Type.ID
    )
    return key

# -------------------- Main flow --------------------
if __name__ == "__main__":
    # Initialize the database
    init_db()

    # Check if vault salt exists
    if vault_exists():
        salt = get_vault_salt()
        print(f"Vault salt found: {salt.hex()}")
    else:
        salt = os.urandom(16)
        set_vault_salt(salt)
        print(f"New vault created with salt: {salt.hex()}")

    # Ask user for password
    password = getpass("Enter your password: ")

    # Derive key
    master_key = derive_master_key(password, salt)
    print(f"Derived key (hex): {master_key.hex()}")  # only for testing



    
def encrypt(plaintext: bytes, key: bytes):
    """
    Encrypt plaintext with AES-256-GCM using `key`.
    Returns: (nonce: bytes, ciphertext: bytes, tag: bytes)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")

    # 1. Generate a fresh 12-byte nonce for GCM (unique per encryption)
    nonce = os.urandom(12)

    # 2. Create AESGCM object from key
    aesgcm = AESGCM(key)

    # 3. Encrypt: AESGCM.encrypt returns ciphertext || tag
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)

    # 4. Split ciphertext and tag (tag is last 16 bytes in GCM)
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    # 5. Return the three components (all bytes)
    return nonce, ciphertext, tag


def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM components and return plaintext bytes.
    Raises InvalidTag if authentication fails.
    """
    if not all(isinstance(x, (bytes, bytearray)) for x in (nonce, ciphertext, tag, key)):
        raise TypeError("nonce, ciphertext, tag and key must be bytes")

    aesgcm = AESGCM(key)
    # AESGCM.decrypt expects ciphertext||tag, so concatenate
    ct_and_tag = ciphertext + tag

    # This will raise cryptography.exceptions.InvalidTag on tamper/wrong key
    plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
    return plaintext
