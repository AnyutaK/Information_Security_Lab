"""
MASTER: Diffie-Hellman + AES/DES + SHA-256 + RSA Signature + Roles

Diffie-Hellman establishes a shared secret between the creator and receiver.
SHA-256 derives the AES/DES key from that shared secret.
RSA signs the ciphertext because Diffie-Hellman is not a signature algorithm.

Install: python -m pip install pycryptodome
"""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


# =========================================================
# CHANGE THESE VALUES ACCORDING TO THE QUESTION
# =========================================================

SYSTEM_NAME = "DH-SecureVault"

SYMMETRIC_ALGORITHM = "AES"  # "AES" or "DES"
AES_KEY_SIZE = 16             # AES: 16, 24 or 32 bytes

ROLE_NAMES = (
    "Client",                 # Creator/sender
    "Lawyer",                 # Authorized receiver
    "Compliance Officer"      # Auditor; cannot decrypt
)

# Educational DH parameters supplied in many lab questions.
DH_P = 7919
DH_G = 2


# =========================================================
# FILES AND STORAGE
# =========================================================

BASE = Path(__file__).resolve().parent / "dh_secure_data"
RECORDS_FILE = BASE / "records.json"
DH_KEYS_FILE = BASE / "dh_keys.json"
RSA_PRIVATE_FILE = BASE / "creator_rsa_private.pem"
RSA_PUBLIC_FILE = BASE / "creator_rsa_public.pem"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_records():
    if not RECORDS_FILE.exists():
        return []
    return json.loads(RECORDS_FILE.read_text())


def save_records(records):
    RECORDS_FILE.write_text(json.dumps(records, indent=2))


# =========================================================
# RSA KEY GENERATION FOR DIGITAL SIGNATURES
# =========================================================

def ensure_rsa_keys():
    BASE.mkdir(exist_ok=True)

    if not RSA_PRIVATE_FILE.exists():
        private_key = RSA.generate(2048)
        RSA_PRIVATE_FILE.write_bytes(private_key.export_key())
        RSA_PUBLIC_FILE.write_bytes(private_key.publickey().export_key())
        os.chmod(RSA_PRIVATE_FILE, 0o600)


def rsa_private_key():
    ensure_rsa_keys()
    return RSA.import_key(RSA_PRIVATE_FILE.read_bytes())


def rsa_public_key():
    ensure_rsa_keys()
    return RSA.import_key(RSA_PUBLIC_FILE.read_bytes())


# =========================================================
# DIFFIE-HELLMAN KEY GENERATION
# =========================================================

def ensure_dh_keys():
    """Generate and persist DH private/public values for creator and receiver."""

    BASE.mkdir(exist_ok=True)

    if not DH_KEYS_FILE.exists():
        creator_private = secrets.randbelow(DH_P - 3) + 2
        receiver_private = secrets.randbelow(DH_P - 3) + 2

        values = {
            "creator_private": creator_private,
            "creator_public": pow(DH_G, creator_private, DH_P),
            "receiver_private": receiver_private,
            "receiver_public": pow(DH_G, receiver_private, DH_P)
        }

        DH_KEYS_FILE.write_text(json.dumps(values, indent=2))
        os.chmod(DH_KEYS_FILE, 0o600)


def dh_values():
    ensure_dh_keys()
    return json.loads(DH_KEYS_FILE.read_text())


def creator_shared_secret():
    values = dh_values()

    return pow(
        values["receiver_public"],
        values["creator_private"],
        DH_P
    )


def receiver_shared_secret():
    values = dh_values()

    return pow(
        values["creator_public"],
        values["receiver_private"],
        DH_P
    )


def show_public_dh_values():
    values = dh_values()

    print("DH prime p:", DH_P)
    print("DH generator g:", DH_G)
    print("Creator public value A:", values["creator_public"])
    print("Receiver public value B:", values["receiver_public"])


# =========================================================
# DERIVE AES/DES KEY FROM SHARED SECRET
# =========================================================

def symmetric_parameters():
    if SYMMETRIC_ALGORITHM == "AES":
        if AES_KEY_SIZE not in (16, 24, 32):
            raise ValueError("AES key size must be 16, 24 or 32 bytes")
        return AES, AES_KEY_SIZE, 16

    if SYMMETRIC_ALGORITHM == "DES":
        return DES, 8, 8

    raise ValueError("Algorithm must be AES or DES")


def derive_symmetric_key(shared_secret):
    module, key_size, iv_size = symmetric_parameters()

    digest = hashlib.sha256(
        str(shared_secret).encode()
    ).digest()

    return digest[:key_size]


# =========================================================
# ENCRYPTION AND DECRYPTION
# =========================================================

def encrypt_data(plaintext, key, iv):
    module, key_size, iv_size = symmetric_parameters()

    cipher = module.new(
        key,
        module.MODE_CBC,
        iv
    )

    return cipher.encrypt(
        pad(plaintext, module.block_size)
    )


def decrypt_data(ciphertext, key, iv):
    module, key_size, iv_size = symmetric_parameters()

    cipher = module.new(
        key,
        module.MODE_CBC,
        iv
    )

    padded_plaintext = cipher.decrypt(ciphertext)

    return unpad(
        padded_plaintext,
        module.block_size
    )


# =========================================================
# HASHING AND RSA SIGNATURE
# =========================================================

def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()


def sign_ciphertext(ciphertext):
    return pkcs1_15.new(
        rsa_private_key()
    ).sign(
        SHA256.new(ciphertext)
    )


def verify_signature(ciphertext, signature):
    try:
        pkcs1_15.new(
            rsa_public_key()
        ).verify(
            SHA256.new(ciphertext),
            signature
        )

        return True

    except (ValueError, TypeError):
        return False


# =========================================================
# RECORD SELECTION
# =========================================================

def select_record(records):
    if not records:
        print("No records available")
        return None

    for record in records:
        print(
            record["id"],
            record["filename"],
            record["timestamp"]
        )

    record_id = input("Enter record ID: ")

    for record in records:
        if record["id"] == record_id:
            return record

    print("Record not found")
    return None


# =========================================================
# CREATOR: ENCRYPT, HASH, SIGN AND STORE
# =========================================================

def upload_record(records):
    path = Path(input("Enter .txt filename: ").strip())

    if path.suffix.lower() != ".txt" or not path.is_file():
        print("A valid .txt file is required")
        return

    module, key_size, iv_size = symmetric_parameters()

    shared_secret = creator_shared_secret()
    symmetric_key = derive_symmetric_key(shared_secret)
    iv = get_random_bytes(iv_size)

    ciphertext = encrypt_data(
        path.read_bytes(),
        symmetric_key,
        iv
    )

    stored_hash = calculate_hash(ciphertext)
    signature = sign_ciphertext(ciphertext)
    values = dh_values()

    record = {
        "id": str(len(records) + 1),
        "filename": path.name,
        "algorithm": SYMMETRIC_ALGORITHM,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "sha256": stored_hash,
        "signature": base64.b64encode(signature).decode(),
        "creator_dh_public": values["creator_public"],
        "receiver_dh_public": values["receiver_public"],
        "timestamp": now(),
        "verifications": []
    }

    records.append(record)
    save_records(records)

    print("\nRecord uploaded successfully")
    print("Record ID:", record["id"])
    print("Algorithm:", SYMMETRIC_ALGORITHM + "-CBC")
    print("Ciphertext:", record["ciphertext"])
    print("IV:", record["iv"])
    print("SHA-256:", stored_hash)
    print("RSA signature:", record["signature"])
    print("Creator DH public value:", record["creator_dh_public"])
    print("Receiver DH public value:", record["receiver_dh_public"])
    print("Timestamp:", record["timestamp"])


def view_creator_records(records):
    if not records:
        print("No records available")
        return

    for record in records:
        print(json.dumps(record, indent=2))


# =========================================================
# RECEIVER: VERIFY AND DECRYPT
# =========================================================

def verify_and_decrypt(records):
    record = select_record(records)

    if record is None:
        return

    ciphertext = base64.b64decode(record["ciphertext"])

    receiver_hash = calculate_hash(ciphertext)
    integrity_valid = receiver_hash == record["sha256"]

    signature = base64.b64decode(record["signature"])
    signature_valid = verify_signature(ciphertext, signature)

    verification = {
        "role": ROLE_NAMES[1],
        "integrity": integrity_valid,
        "signature": signature_valid,
        "timestamp": now()
    }

    record["verifications"].append(verification)
    save_records(records)

    print("Integrity:", "VALID" if integrity_valid else "FAILED")
    print("RSA signature:", "VALID" if signature_valid else "INVALID")
    print("Verification timestamp:", verification["timestamp"])

    if not (integrity_valid and signature_valid):
        print("Verification failed")
        print("Decryption denied")
        return

    shared_secret = receiver_shared_secret()
    symmetric_key = derive_symmetric_key(shared_secret)
    iv = base64.b64decode(record["iv"])

    try:
        plaintext = decrypt_data(
            ciphertext,
            symmetric_key,
            iv
        )

        print("Recovered plaintext:\n" + plaintext.decode())

    except (ValueError, UnicodeDecodeError):
        print("Decryption failed")


# =========================================================
# AUDITOR: VERIFY WITHOUT DECRYPTING
# =========================================================

def audit_record(records):
    record = select_record(records)

    if record is None:
        return

    ciphertext = base64.b64decode(record["ciphertext"])
    integrity_valid = calculate_hash(ciphertext) == record["sha256"]

    signature = base64.b64decode(record["signature"])
    signature_valid = verify_signature(ciphertext, signature)

    verification = {
        "role": ROLE_NAMES[2],
        "integrity": integrity_valid,
        "signature": signature_valid,
        "timestamp": now()
    }

    record["verifications"].append(verification)
    save_records(records)

    print("\nRecord ID:", record["id"])
    print("Filename:", record["filename"])
    print("Creator DH public value:", record["creator_dh_public"])
    print("Receiver DH public value:", record["receiver_dh_public"])
    print("SHA-256:", record["sha256"])
    print("Upload timestamp:", record["timestamp"])
    print("Integrity:", "VALID" if integrity_valid else "FAILED")
    print("RSA signature:", "VALID" if signature_valid else "INVALID")
    print("Audit timestamp:", verification["timestamp"])
    print("Plaintext access: DENIED")


# =========================================================
# TAMPERING DEMONSTRATION
# =========================================================

def tamper_record(records):
    record = select_record(records)

    if record is None:
        return

    ciphertext = bytearray(
        base64.b64decode(record["ciphertext"])
    )

    ciphertext[0] ^= 1

    record["ciphertext"] = base64.b64encode(
        bytes(ciphertext)
    ).decode()

    save_records(records)
    print("One ciphertext byte was modified")


# =========================================================
# ROLE MENUS
# =========================================================

def creator_menu(records):
    while True:
        print(f"\n--- {ROLE_NAMES[0]} ---")
        print("1. Upload encrypted record")
        print("2. View encrypted records")
        print("3. Show public DH values")
        print("4. Tampering demonstration")
        print("0. Back")

        choice = input("Choice: ")

        if choice == "1":
            upload_record(records)
        elif choice == "2":
            view_creator_records(records)
        elif choice == "3":
            show_public_dh_values()
        elif choice == "4":
            tamper_record(records)
        elif choice == "0":
            return
        else:
            print("Invalid choice")


def receiver_menu(records):
    while True:
        print(f"\n--- {ROLE_NAMES[1]} ---")
        print("1. View available records")
        print("2. Verify and decrypt")
        print("3. Show public DH values")
        print("0. Back")

        choice = input("Choice: ")

        if choice == "1":
            select_record(records)
        elif choice == "2":
            verify_and_decrypt(records)
        elif choice == "3":
            show_public_dh_values()
        elif choice == "0":
            return
        else:
            print("Invalid choice")


def main():
    BASE.mkdir(exist_ok=True)
    ensure_rsa_keys()
    ensure_dh_keys()
    records = load_records()

    print(
        "DH shared secrets match:",
        creator_shared_secret() == receiver_shared_secret()
    )

    while True:
        print(f"\n========== {SYSTEM_NAME} ==========")
        print("1.", ROLE_NAMES[0])
        print("2.", ROLE_NAMES[1])
        print("3.", ROLE_NAMES[2])
        print("4. Exit")

        choice = input("Select role: ")

        if choice == "1":
            creator_menu(records)
        elif choice == "2":
            receiver_menu(records)
        elif choice == "3":
            audit_record(records)
        elif choice == "4":
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
