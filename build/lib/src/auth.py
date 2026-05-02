import logging
from argon2.low_level import hash_secret_raw, Type
from .models import MasterKey, Salt

logger = logging.getLogger(__name__)

class Authenticator:
    """Handle master password and key derivation."""
    
    # Argon2id parameters
    TIME_COST = 2
    MEMORY_COST = 102400  # 100 MiB
    PARALLELISM = 8
    HASH_LEN = 32         # AES-256 key

    @classmethod
    def derive_key(cls, password: str, salt: Salt) -> MasterKey:
        """Derive master key using Argon2id."""
        if not isinstance(password, str):
            raise TypeError("password must be str")
        if not isinstance(salt, bytes):
            raise TypeError("salt must be bytes")

        key_bytes = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=cls.TIME_COST,
            memory_cost=cls.MEMORY_COST,
            parallelism=cls.PARALLELISM,
            hash_len=cls.HASH_LEN,
            type=Type.ID
        )
        logger.debug("Derived MasterKey")
        return MasterKey(key_bytes)
