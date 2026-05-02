import secrets
import logging
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .models import MasterKey, Nonce, Tag, Ciphertext

logger = logging.getLogger(__name__)

class CryptoEngine:
    """Handle AES-256-GCM encryption and decryption."""
    
    NONCE_LEN = 12
    TAG_LEN = 16

    def __init__(self, key: MasterKey):
        if not isinstance(key, bytes):
            raise TypeError("key must be MasterKey (bytes)")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> Tuple[Nonce, Ciphertext, Tag]:
        """Encrypt plaintext. Return (nonce, ciphertext, tag)."""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        nonce = secrets.token_bytes(self.NONCE_LEN)
        ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, None)
        
        ciphertext = ct_and_tag[:-self.TAG_LEN]
        tag = ct_and_tag[-self.TAG_LEN:]
        
        logger.debug("Encrypted payload")
        return Nonce(nonce), Ciphertext(ciphertext), Tag(tag)

    def decrypt(self, nonce: Nonce, ciphertext: Ciphertext, tag: Tag) -> bytes:
        """Decrypt payload. Raise InvalidTag on failure."""
        if not all(isinstance(x, bytes) for x in (nonce, ciphertext, tag)):
            raise TypeError("nonce, ciphertext, and tag must be bytes")

        ct_and_tag = ciphertext + tag
        plaintext = self._aesgcm.decrypt(nonce, ct_and_tag, None)
        
        logger.debug("Decrypted payload")
        return plaintext
