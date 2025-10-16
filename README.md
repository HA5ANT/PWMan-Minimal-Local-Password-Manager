## 🔐 PWMan — Minimal Local Password Manager

PWMan is a small, offline password manager you run from the command line. It uses modern, safe primitives and stores encrypted entries in a local SQLite database.

### What it uses
- Argon2id for key derivation (produces a 32‑byte AES‑256 key)
- AES‑256‑GCM for authenticated encryption (AEAD)
- SQLite for local storage

### Features
- Initialize a vault with a random salt
- Add entries (name, username, secret)
- List entries (metadata only)
- View/decrypt a single entry on demand
- Delete entries
- Works fully offline

### Install
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Usage
Run the CLI with Python’s module runner:
```bash
python -m src.cli --help
```
All commands accept `--db` to point at a specific database path (defaults to `vault.db`).

#### Initialize a vault
```bash
python -m src.cli init
```
If no vault exists, this creates the SQLite DB and a new 16‑byte random salt, then prints the salt (hex) once with a warning. Copy and store it safely. You may need it if you ever delete the DB and want to re‑create/verify the vault state.

#### Add an entry
```bash
python -m src.cli add
```
Prompts for: entry name, username, and secret (via getpass). Derives the master key from the stored vault salt and your master password, encrypts the secret with AES‑GCM, and stores `(nonce, ciphertext, tag)` as BLOBs.

#### List entries
```bash
python -m src.cli list
```
Shows id, name, username, created_at. No secrets are printed.

#### View (decrypt) an entry
```bash
python -m src.cli view <id>
```
Prompts for your master password, derives the key, decrypts the selected entry, and prints the secret once. If the password is wrong or data is corrupted, you’ll see: "Decryption failed — wrong master password or data corrupted."

#### Delete an entry
```bash
python -m src.cli delete <id>
```

### How it works (short)

#### Key derivation
`src/crypto.py` derives a 32‑byte AES key from your master password and the vault salt using Argon2id with:
- `time_cost = 2`, `memory_cost = 102400` KiB (~100 MiB), `parallelism = 8`, `hash_len = 32`

#### Encryption
`encrypt(plaintext, key)` uses `AESGCM` with:
- 12‑byte random nonce per encryption (`os.urandom(12)`)
- 16‑byte GCM tag
- Returns `(nonce, ciphertext, tag)`

`decrypt(nonce, ciphertext, tag, key)` returns the plaintext or raises `InvalidTag` if authentication fails.

#### Storage schema
`src/storage.py` manages a SQLite DB with two tables:
- `vault(id=1, salt BLOB NOT NULL)` — single row storing the vault salt
- `passwords(id, name, username, nonce BLOB, ciphertext BLOB, tag BLOB, created_at)`

Helper functions cover initialization, salt get/set, and CRUD for entries.

### Testing
Run the unit tests with pytest:
```bash
pytest -q
```
Included tests (`tests/test_crypto_storage.py`):
- Round‑trip: derive → encrypt → store → fetch → decrypt == original
- Invalid key: decrypt with wrong password raises `InvalidTag`

### Security notes
- The master key is never printed or stored.
- Decrypted secrets are only printed on explicit `view` and only once.
- The vault salt is printed once on `init`. Back it up safely if you need it for recovery workflows.
- Choose a strong master password; Argon2id parameters are set for a solid default, but you can raise time/memory on capable machines.

### Project layout
```
src/
  cli.py       # CLI entrypoint (argparse)
  crypto.py    # KDF + AES‑GCM encrypt/decrypt helpers
  storage.py   # SQLite schema and helpers
tests/
  test_crypto_storage.py
```
