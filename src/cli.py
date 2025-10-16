import argparse
from getpass import getpass
import sys
from typing import Optional

from .storage import (
    init_db,
    get_vault_salt,
    set_vault_salt,
    vault_exists,
    add_entry,
    list_entries,
    get_entry,
    delete_entry,
)
from .crypto import derive_master_key, encrypt, decrypt


def cmd_init(db_path: str) -> int:
    init_db(db_path)
    salt = get_vault_salt(db_path)
    if salt is None:
        import os

        salt = os.urandom(16)
        set_vault_salt(salt, db_path)
        print("Vault created.")
        print(
            "WARNING: This is your vault salt (hex). Copy it now — you'll need it if the DB is deleted:"
        )
        print(salt.hex())
    else:
        print("Vault already exists. Nothing to do.")
    return 0


def _derive_key_from_db(db_path: str) -> bytes:
    salt = get_vault_salt(db_path)
    if not salt:
        print("No vault salt found. Run 'init' first.")
        sys.exit(1)
    password = getpass("Enter your master password: ")
    return derive_master_key(password, salt)


def cmd_add(db_path: str) -> int:
    key = _derive_key_from_db(db_path)

    name = input("Entry name: ").strip()
    username = input("Username: ").strip()
    secret = getpass("Secret (e.g., password or token): ").encode()

    nonce, ciphertext, tag = encrypt(secret, key)
    entry_id = add_entry(name, username, nonce, ciphertext, tag, db_path)
    print(f"Added entry id={entry_id}.")
    return 0


def cmd_list(db_path: str) -> int:
    rows = list_entries(db_path)
    if not rows:
        print("No entries.")
        return 0
    for r in rows:
        print(f"{r['id']}: {r['name']} ({r['username']}) - {r['created_at']}")
    return 0


def cmd_view(db_path: str, entry_id: int) -> int:
    row = get_entry(entry_id, db_path)
    if row is None:
        print("Entry not found.")
        return 1

    key = _derive_key_from_db(db_path)
    try:
        plaintext = decrypt(row["nonce"], row["ciphertext"], row["tag"], key)
    except Exception:
        print("Decryption failed — wrong master password or data corrupted.")
        return 2

    # One-time display; do not persist or log
    try:
        decoded = plaintext.decode()
    except UnicodeDecodeError:
        decoded = plaintext.hex()
    print(decoded)
    return 0


def cmd_delete(db_path: str, entry_id: int) -> int:
    ok = delete_entry(entry_id, db_path)
    if ok:
        print("Deleted.")
        return 0
    print("Entry not found.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pwman", description="Password manager CLI")
    parser.add_argument("--db", default="vault.db", help="Path to database file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize vault database and salt")
    sub.add_parser("add", help="Add a new entry (name, username, secret)")
    sub.add_parser("list", help="List entries (metadata only)")

    p_view = sub.add_parser("view", help="View/decrypt an entry by id")
    p_view.add_argument("id", type=int, help="Entry id")

    p_del = sub.add_parser("delete", help="Delete an entry by id")
    p_del.add_argument("id", type=int, help="Entry id")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = args.db
    if args.command == "init":
        return cmd_init(db_path)
    if args.command == "add":
        return cmd_add(db_path)
    if args.command == "list":
        return cmd_list(db_path)
    if args.command == "view":
        return cmd_view(db_path, args.id)
    if args.command == "delete":
        return cmd_delete(db_path, args.id)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())


