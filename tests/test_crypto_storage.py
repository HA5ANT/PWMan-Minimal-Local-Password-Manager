import os
import pytest
from src.storage import init_db, set_vault_salt, add_entry, get_entry
from src.auth import Authenticator
from src.crypto import CryptoEngine
from src.models import Salt, Nonce, Ciphertext, Tag
from cryptography.exceptions import InvalidTag


def test_roundtrip(tmp_path):
    db_path = str(tmp_path / "vault.db")
    init_db(db_path)

    salt = Salt(os.urandom(16))
    set_vault_salt(salt, db_path)

    key = Authenticator.derive_key("password123", salt)
    engine = CryptoEngine(key)

    plaintext = b"supersecret"
    nonce, ct, tag = engine.encrypt(plaintext)
    entry_id = add_entry("example", "alice", nonce, ct, tag, db_path)

    row = get_entry(entry_id, db_path)
    assert row is not None
    
    # Use same key to decrypt
    pt = engine.decrypt(Nonce(row["nonce"]), Ciphertext(row["ciphertext"]), Tag(row["tag"]))
    assert pt == plaintext


def test_bad_key(tmp_path):
    db_path = str(tmp_path / "vault.db")
    init_db(db_path)

    salt = Salt(os.urandom(16))
    set_vault_salt(salt, db_path)

    correct_key = Authenticator.derive_key("correct", salt)
    engine_correct = CryptoEngine(correct_key)
    
    nonce, ct, tag = engine_correct.encrypt(b"data")
    entry_id = add_entry("ex", "bob", nonce, ct, tag, db_path)

    row = get_entry(entry_id, db_path)
    assert row is not None
    
    wrong_key = Authenticator.derive_key("wrong", salt)
    engine_wrong = CryptoEngine(wrong_key)
    
    with pytest.raises(InvalidTag):
        engine_wrong.decrypt(Nonce(row["nonce"]), Ciphertext(row["ciphertext"]), Tag(row["tag"]))
