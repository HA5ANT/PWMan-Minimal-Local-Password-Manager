# src/storage.py
"""
SQLite storage layer for PWMan.

Usage:
    from storage import init_db, set_vault_salt, get_vault_salt, add_entry, list_entries, get_entry, delete_entry

This module stores:
 - vault table (id=1 row): salt (BLOB)
 - passwords table: id, name, username, nonce (BLOB), ciphertext (BLOB), tag (BLOB)
"""

from typing import Optional, List, Dict, Tuple
import sqlite3
import os

DEFAULT_DB = "vault.db"


def get_connection(db_path: str = DEFAULT_DB) -> sqlite3.Connection:
    """Return a sqlite3 connection with row factory set to sqlite3.Row."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB) -> None:
    """Create the required tables if they don't exist."""
    conn = get_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL
        );
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            tag BLOB NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    conn.commit()
    conn.close()


# ----- Vault (salt) helpers -----


def set_vault_salt(salt: bytes, db_path: str = DEFAULT_DB) -> None:
    """
    Store the vault salt (as BLOB). Uses id=1 row; will replace existing.
    salt: bytes
    """
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")

    conn = get_connection(db_path)
    cur = conn.cursor()

    # Use INSERT OR REPLACE to ensure a single row with id=1
    cur.execute(
        "INSERT OR REPLACE INTO vault (id, salt) VALUES (?, ?);",
        (1, sqlite3.Binary(salt)),
    )
    conn.commit()
    conn.close()


def get_vault_salt(db_path: str = DEFAULT_DB) -> Optional[bytes]:
    """
    Return the vault salt as bytes, or None if no vault exists.
    """
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT salt FROM vault WHERE id = 1;")
    row = cur.fetchone()
    conn.close()
    if row is None:
        return None
    return row["salt"]  # already bytes


# ----- Password entries helpers -----


def add_entry(
    name: str,
    username: str,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    db_path: str = DEFAULT_DB,
) -> int:
    """
    Insert an encrypted entry.
    Returns the inserted entry id (int).
    """
    for v in (nonce, ciphertext, tag):
        if not isinstance(v, (bytes, bytearray)):
            raise TypeError("nonce, ciphertext and tag must be bytes")

    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO passwords (name, username, nonce, ciphertext, tag)
        VALUES (?, ?, ?, ?, ?)
        """,
        (name, username, sqlite3.Binary(nonce), sqlite3.Binary(ciphertext), sqlite3.Binary(tag)),
    )
    conn.commit()
    entry_id = cur.lastrowid
    conn.close()
    return entry_id


def get_entry(entry_id: int, db_path: str = DEFAULT_DB) -> Optional[Dict]:
    """
    Return a dictionary containing all fields for the given entry id.
    The BLOB fields are returned as bytes.
    """
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM passwords WHERE id = ?;", (entry_id,))
    row = cur.fetchone()
    conn.close()
    if row is None:
        return None

    return {
        "id": row["id"],
        "name": row["name"],
        "username": row["username"],
        "nonce": row["nonce"],
        "ciphertext": row["ciphertext"],
        "tag": row["tag"],
        "created_at": row["created_at"],
    }


def list_entries(db_path: str = DEFAULT_DB) -> List[Dict]:
    """
    Return a list of entries with minimal metadata (id, name, username, created_at).
    Does NOT return ciphertext/nonce/tag to avoid accidental printing of secrets.
    """
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, name, username, created_at FROM passwords ORDER BY name COLLATE NOCASE;")
    rows = cur.fetchall()
    conn.close()

    out = []
    for r in rows:
        out.append({"id": r["id"], "name": r["name"], "username": r["username"], "created_at": r["created_at"]})
    return out


def delete_entry(entry_id: int, db_path: str = DEFAULT_DB) -> bool:
    """
    Delete an entry by id. Returns True if a row was deleted, False otherwise.
    """
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM passwords WHERE id = ?;", (entry_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted


# ----- Utility helpers -----


def vault_exists(db_path: str = DEFAULT_DB) -> bool:
    """Return True if a vault salt exists in the DB."""
    return get_vault_salt(db_path) is not None


def remove_db_file(db_path: str = DEFAULT_DB) -> None:
    """Dangerous: delete the DB file from disk. Use only for tests."""
    try:
        os.remove(db_path)
    except FileNotFoundError:
        pass


# ----- Demo / quick test (non-destructive, safe) -----
if __name__ == "__main__":
    # Quick demo to create DB and show vault salt status.
    print("Initializing DB (vault.db)...")
    init_db()
    salt = get_vault_salt()
    if salt:
        print(f"Vault salt already present: {salt.hex()}")
    else:
        print("No vault salt found. Generating a test salt (not stored).")
        import os
        test_salt = os.urandom(16)
        print(f"Test salt (hex): {test_salt.hex()}")

    print("DB initialized. Use get_vault_salt(), set_vault_salt(), add_entry(), list_entries(), get_entry().")
