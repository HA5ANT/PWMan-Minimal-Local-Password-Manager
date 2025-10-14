from getpass import getpass
import os
from argon2.low_level import hash_secret_raw, Type

def derive_key():
    # 1️⃣ Get the master password
    passwd = getpass("Enter Your Password: ")

    # 2️⃣ Get salt or generate one
    salt_input = input("Salt (leave empty to generate a new one, enter hex if you have one): ")
    if salt_input == "":
        salt = os.urandom(16)  # 16 bytes random salt
        print(f"Generated salt (keep this safe!): {salt.hex()}")
    else:
        try:
            salt = bytes.fromhex(salt_input)  # convert hex string to bytes
        except ValueError:
            print("Invalid hex. Generating a new random salt instead.")
            salt = os.urandom(16)
            print(f"Generated salt (keep this safe!): {salt.hex()}")

    # 3️⃣ Derive the master key using Argon2id
    master_key = hash_secret_raw(
        secret=passwd.encode(),  # convert password to bytes
        salt=salt,
        time_cost=2,            # number of iterations
        memory_cost=102400,     # memory in KiB (~100 MB)
        parallelism=8,          # threads
        hash_len=32,            # output length in bytes (AES-256)
        type=Type.ID
    )

    print(f"Derived master key (hex): {master_key.hex()}")
    return master_key, salt

# Test run
if __name__ == "__main__":
    derive_key()
