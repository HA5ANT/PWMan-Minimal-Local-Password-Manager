from typing import NewType

# Type safety for sensitive data
MasterKey = NewType("MasterKey", bytes)
Salt = NewType("Salt", bytes)
Nonce = NewType("Nonce", bytes)
Tag = NewType("Tag", bytes)
Ciphertext = NewType("Ciphertext", bytes)
