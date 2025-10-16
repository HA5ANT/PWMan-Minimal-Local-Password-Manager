from argon2.low_level import hash_secret_raw, Type
import os
import logging
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Minimal logging setup (library-safe): default WARNING, opt-in DEBUG for devs
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())

def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte master key from a password and salt using Argon2id.
    """
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")

    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=102400,  # ~100 MB
        parallelism=8,
        hash_len=32,         # AES-256 key
        type=Type.ID
    )
    logger.debug("Derived master key of length %d bytes", len(key))
    return key

def encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
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
    logger.debug(
        "Encrypted payload with nonce length %d, ciphertext length %d, tag length %d",
        len(nonce), len(ciphertext), len(tag),
    )
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
    logger.debug("Decrypted payload with plaintext length %d", len(plaintext))
    return plaintext
