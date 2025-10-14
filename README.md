# 🔐 Password Manager (PWMan)

A simple local password manager built in Python using:
- Argon2id for key derivation
- AES-256-GCM for encryption
- SQLite for local storage

## Features
- Create and manage encrypted vaults
- Command-line interface
- No internet connection required

## Setup
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
