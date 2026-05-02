import secrets
import os
from src.storage import init_db, set_vault_salt, set_verification, add_entry
from src.auth import Authenticator
from src.crypto import CryptoEngine
from src.models import Salt, Nonce, Ciphertext, Tag

def create_demo():
    name = "Showcase.db"
    if os.path.exists(name): os.remove(name)
    password = "password123"
    
    init_db(name)
    salt = Salt(secrets.token_bytes(16))
    set_vault_salt(salt, name)
    
    key = Authenticator.derive_key(password, salt)
    engine = CryptoEngine(key)
    
    # Verification
    v_nonce, v_ct, v_tag = engine.encrypt(b"PWMAN_VERIFY")
    set_verification(v_nonce, v_ct, v_tag, name)
    
    # Generate 20+ Entries
    entries = [(f"Service_{i}", f"user_{i}", f"pass_secret_{i}") for i in range(25)]
    
    for n, u, s in entries:
        nonce, ct, tag = engine.encrypt(s.encode())
        add_entry(n, u, nonce, ct, tag, name)
    
    print(f"Demo vault '{name}' created with 25 entries.")

if __name__ == "__main__":
    create_demo()
