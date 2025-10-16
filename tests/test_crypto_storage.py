import os
import sqlite3
import pytest

from src.storage import init_db, set_vault_salt, add_entry, get_entry, remove_db_file
from src.crypto import derive_master_key, encrypt, decrypt
from cryptography.exceptions import InvalidTag


def test_roundtrip(tmp_path):
    db_path = str(tmp_path / "vault.db")
    init_db(db_path)

    salt = os.urandom(16)
    set_vault_salt(salt, db_path)

    key = derive_master_key("password123", salt)

    nonce, ct, tag = encrypt(b"supersecret", key)
    entry_id = add_entry("example", "alice", nonce, ct, tag, db_path)

    row = get_entry(entry_id, db_path)
    assert row is not None
    pt = decrypt(row["nonce"], row["ciphertext"], row["tag"], key)
    assert pt == b"supersecret"


def test_bad_key(tmp_path):
    db_path = str(tmp_path / "vault.db")
    init_db(db_path)

    salt = os.urandom(16)
    set_vault_salt(salt, db_path)

    key = derive_master_key("correct", salt)
    nonce, ct, tag = encrypt(b"data", key)
    entry_id = add_entry("ex", "bob", nonce, ct, tag, db_path)

    row = get_entry(entry_id, db_path)
    assert row is not None
    wrong_key = derive_master_key("wrong", salt)
    with pytest.raises(InvalidTag):
        decrypt(row["nonce"], row["ciphertext"], row["tag"], wrong_key)


