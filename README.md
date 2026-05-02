# 🔐 PWMan — Minimal Local Password Manager

PWMan is a lightweight, offline, and highly secure password manager for Windows. It features a conversational, interactive CLI with a focus on cryptographic integrity and multiple vault support.

## 🛠 Features
- **Auto-Lock Security**: Session automatically clears master key after inactivity (Timer currently in development).
- **Contextual Menu**: Flattened, state-aware navigation (Vault vs. Entry modes).
- **Transient Display**: Secrets clear from screen with a **visible 10s countdown**.
- **Rich UI**: High-end terminal experience with professional color palettes and progress spinners.
- **Multi-Vault Support**: Create, open, and delete multiple encrypted vaults (`.db` files) with ease.
- **Strong Encryption**: Argon2id for key derivation and AES-256-GCM for authenticated encryption.
- **Type Safe**: Rigorous Python implementation with `NewType` safety for sensitive data.
- **Visual UI**: Enhanced with ASCII banners, custom color themes, and formatted output.

## 🚀 Getting Started

### Prerequisites
- Python 3.9+

### Installation
```bash
# Clone the repository
git clone https://github.com/your-username/pwman-minimal-local-password-manager.git
cd pwman-minimal-local-password-manager

# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install the package
pip install .
```

### Usage
Start the interactive shell:
```bash
pwman
```

Once inside the shell, use your arrow keys to navigate the menu:

#### 📂 Vault Management
- **Create Vault**: Set a vault name and a master password immediately.
- **Open Vault**: Switch between your existing `.db` vault files.
- **Delete Vault**: Permanently remove a vault and all its contents (with safety confirmation).

#### 🔑 Entry Management
- **Add Entry**: Securely store a new credential (name, username, secret).
- **List/View Entries**: Browse your credentials and decrypt secrets on demand.
- **Delete Entry**: Remove specific credentials from the active vault.

## 🏗 Architecture

### Modern Patterns
- **`Authenticator`**: Centralized logic for master password handling and Argon2id KDF.
- **`CryptoEngine`**: Class-based AES-256-GCM implementation.
- **`models.py`**: Explicit type safety for keys, salts, and nonces.
- **`Session`**: Global state management for tracking the active vault.

### Technical Specs
- **KDF**: Argon2id (`time=2`, `memory=100MB`, `parallelism=8`).
- **Encryption**: AES-256-GCM with 12-byte random nonces (`secrets` module).
- **Storage**: SQLite DB with BLOB storage for cryptographic components.

## 🧪 Testing
Verify the cryptographic integrity and storage logic:
```bash
pip install ".[dev]"
pytest -q
```

## 🔒 Security
- **No Persistence**: Master keys are only kept in memory during the active derivation/decryption step.
- **Strong Entropy**: Uses Python's `secrets` module for all random byte generation.
- **AEAD**: Uses GCM to provide both confidentiality and data integrity.

---
*Intended for Windows. Use responsibly.*
