"""
MASTER: AES/DES + SHA-256 + Schnorr Signature + Role-Based Access

Install dependency:
    python -m pip install pycryptodome

The small Schnorr parameters are suitable only for an educational lab demonstration.
"""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# =========================================================
# CHANGE THESE ACCORDING TO THE QUESTION
# =========================================================

SYSTEM_NAME = "SchnorrSecure"

SYMMETRIC_ALGORITHM = "AES"  # "AES" or "DES"
AES_KEY_SIZE = 16             # AES: 16, 24 or 32 bytes
AUTO_GENERATE_IV = True

ROLE_NAMES = (
    "Client",                 # Creator/sender
    "Lawyer",                 # Authorized receiver
    "Compliance Officer"      # Auditor; cannot decrypt
)


# =========================================================
# STORAGE
# =========================================================

BASE = Path(__file__).resolve().parent / "schnorr_secure_data"
RECORDS_FILE = BASE / "records.json"
SCHNORR_PRIVATE_FILE = BASE / "creator_schnorr_private.json"
SCHNORR_PUBLIC_FILE = BASE / "creator_schnorr_public.json"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_records():
    if not RECORDS_FILE.exists():
        return []
    return json.loads(RECORDS_FILE.read_text())


def save_records(records):
    RECORDS_FILE.write_text(json.dumps(records, indent=2))


# =========================================================
# SCHNORR KEY GENERATION
# =========================================================

# q divides p-1 and g has order q modulo p.
SCHNORR_P = 23
SCHNORR_Q = 11
SCHNORR_G = 2


def ensure_schnorr_keys():
    BASE.mkdir(exist_ok=True)

    if not SCHNORR_PRIVATE_FILE.exists():
        private_key = secrets.randbelow(SCHNORR_Q - 1) + 1
        public_value = pow(SCHNORR_G, private_key, SCHNORR_P)

        SCHNORR_PRIVATE_FILE.write_text(
            json.dumps({"x": private_key})
        )

        SCHNORR_PUBLIC_FILE.write_text(
            json.dumps(
                {
                    "p": SCHNORR_P,
                    "q": SCHNORR_Q,
                    "g": SCHNORR_G,
                    "y": public_value
                },
                indent=2
            )
        )

        os.chmod(SCHNORR_PRIVATE_FILE, 0o600)


def schnorr_private_key():
    ensure_schnorr_keys()
    return json.loads(SCHNORR_PRIVATE_FILE.read_text())["x"]


def schnorr_public_key():
    ensure_schnorr_keys()
    return json.loads(SCHNORR_PUBLIC_FILE.read_text())


# =========================================================
# SCHNORR SIGNATURE AND VERIFICATION
# =========================================================

def schnorr_challenge(data, commitment, q):
    challenge_data = data + str(commitment).encode()

    return int.from_bytes(
        hashlib.sha256(challenge_data).digest(),
        "big"
    ) % q


def schnorr_sign(data):
    private_key = schnorr_private_key()
    public = schnorr_public_key()
    p, q, g = public["p"], public["q"], public["g"]

    random_nonce = secrets.randbelow(q - 1) + 1
    commitment = pow(g, random_nonce, p)
    challenge = schnorr_challenge(data, commitment, q)
    response = (random_nonce + challenge * private_key) % q

    return {
        "challenge": challenge,
        "response": response
    }


def schnorr_verify(data, signature):
    public = schnorr_public_key()
    p, q, g, y = public["p"], public["q"], public["g"], public["y"]
    challenge = signature["challenge"]
    response = signature["response"]

    if not (0 <= challenge < q and 0 <= response < q):
        return False

    # commitment = g^response * (y^challenge)^(-1) mod p
    public_component = pow(y, challenge, p)
    reconstructed_commitment = (
        pow(g, response, p)
        * pow(public_component, -1, p)
    ) % p

    expected_challenge = schnorr_challenge(
        data,
        reconstructed_commitment,
        q
    )

    return expected_challenge == challenge


# =========================================================
# SYMMETRIC ENCRYPTION PARAMETERS
# =========================================================

def symmetric_parameters():
    if SYMMETRIC_ALGORITHM == "AES":
        if AES_KEY_SIZE not in (16, 24, 32):
            raise ValueError("AES key size must be 16, 24 or 32 bytes")
        return AES, AES_KEY_SIZE, 16

    if SYMMETRIC_ALGORITHM == "DES":
        return DES, 8, 8

    raise ValueError("Algorithm must be AES or DES")


def read_symmetric_key():
    module, key_size, iv_size = symmetric_parameters()

    key = input(
        f"Enter exactly {key_size} characters for the "
        f"{SYMMETRIC_ALGORITHM} key: "
    ).encode()

    if len(key) != key_size:
        raise ValueError(f"Key must be exactly {key_size} bytes")

    return key


def obtain_iv():
    module, key_size, iv_size = symmetric_parameters()

    if AUTO_GENERATE_IV:
        return get_random_bytes(iv_size)

    iv = input(f"Enter exactly {iv_size} characters for the IV: ").encode()

    if len(iv) != iv_size:
        raise ValueError(f"IV must be exactly {iv_size} bytes")

    return iv


def encrypt_data(plaintext, key, iv):
    module, key_size, iv_size = symmetric_parameters()
    cipher = module.new(key, module.MODE_CBC, iv)

    return cipher.encrypt(
        pad(plaintext, module.block_size)
    )


def decrypt_data(ciphertext, key, iv):
    module, key_size, iv_size = symmetric_parameters()
    cipher = module.new(key, module.MODE_CBC, iv)

    return unpad(
        cipher.decrypt(ciphertext),
        module.block_size
    )


def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()


# =========================================================
# RECORD SELECTION
# =========================================================

def select_record(records):
    if not records:
        print("No records available")
        return None

    for record in records:
        print(record["id"], record["filename"], record["timestamp"])

    record_id = input("Enter record ID: ")

    for record in records:
        if record["id"] == record_id:
            return record

    print("Record not found")
    return None


# =========================================================
# CREATOR
# =========================================================

def upload_record(records):
    path = Path(input("Enter .txt filename: ").strip())

    if path.suffix.lower() != ".txt" or not path.is_file():
        print("A valid .txt file is required")
        return

    try:
        key = read_symmetric_key()
        iv = obtain_iv()
    except ValueError as error:
        print(error)
        return

    ciphertext = encrypt_data(path.read_bytes(), key, iv)
    stored_hash = calculate_hash(ciphertext)
    signature = schnorr_sign(ciphertext)

    record = {
        "id": str(len(records) + 1),
        "filename": path.name,
        "algorithm": SYMMETRIC_ALGORITHM,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "sha256": stored_hash,
        "schnorr_signature": signature,
        "timestamp": now(),
        "verifications": []
    }

    records.append(record)
    save_records(records)

    print("\nRecord uploaded successfully")
    print("Record ID:", record["id"])
    print("Ciphertext:", record["ciphertext"])
    print("IV:", record["iv"])
    print("SHA-256:", stored_hash)
    print("Schnorr signature:", signature)
    print("Timestamp:", record["timestamp"])


def view_creator_records(records):
    if not records:
        print("No records available")
        return

    for record in records:
        print(json.dumps(record, indent=2))


# =========================================================
# RECEIVER
# =========================================================

def verify_and_decrypt(records):
    record = select_record(records)

    if record is None:
        return

    ciphertext = base64.b64decode(record["ciphertext"])
    integrity_valid = calculate_hash(ciphertext) == record["sha256"]
    signature_valid = schnorr_verify(
        ciphertext,
        record["schnorr_signature"]
    )

    verification = {
        "role": ROLE_NAMES[1],
        "integrity": integrity_valid,
        "signature": signature_valid,
        "timestamp": now()
    }

    record["verifications"].append(verification)
    save_records(records)

    print("Integrity:", "VALID" if integrity_valid else "FAILED")
    print("Schnorr signature:", "VALID" if signature_valid else "INVALID")
    print("Verification timestamp:", verification["timestamp"])

    if not (integrity_valid and signature_valid):
        print("Verification failed")
        print("Decryption denied")
        return

    try:
        key = read_symmetric_key()
        iv = base64.b64decode(record["iv"])
        plaintext = decrypt_data(ciphertext, key, iv)
        print("Recovered plaintext:\n" + plaintext.decode())

    except (ValueError, UnicodeDecodeError):
        print("Incorrect key or corrupted data")


# =========================================================
# AUDITOR
# =========================================================

def audit_record(records):
    record = select_record(records)

    if record is None:
        return

    ciphertext = base64.b64decode(record["ciphertext"])
    integrity_valid = calculate_hash(ciphertext) == record["sha256"]
    signature_valid = schnorr_verify(
        ciphertext,
        record["schnorr_signature"]
    )

    verification = {
        "role": ROLE_NAMES[2],
        "integrity": integrity_valid,
        "signature": signature_valid,
        "timestamp": now()
    }

    record["verifications"].append(verification)
    save_records(records)

    public = schnorr_public_key()

    print("\nRecord ID:", record["id"])
    print("Filename:", record["filename"])
    print("SHA-256:", record["sha256"])
    print("Schnorr signature:", record["schnorr_signature"])
    print("Schnorr public key:", public)
    print("Upload timestamp:", record["timestamp"])
    print("Integrity:", "VALID" if integrity_valid else "FAILED")
    print("Signature:", "VALID" if signature_valid else "INVALID")
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
# MENUS
# =========================================================

def creator_menu(records):
    while True:
        print(f"\n--- {ROLE_NAMES[0]} ---")
        print("1. Upload record")
        print("2. View encrypted records")
        print("3. Tampering demonstration")
        print("0. Back")

        choice = input("Choice: ")

        if choice == "1":
            upload_record(records)
        elif choice == "2":
            view_creator_records(records)
        elif choice == "3":
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
        print("0. Back")

        choice = input("Choice: ")

        if choice == "1":
            select_record(records)
        elif choice == "2":
            verify_and_decrypt(records)
        elif choice == "0":
            return
        else:
            print("Invalid choice")


def main():
    BASE.mkdir(exist_ok=True)
    ensure_schnorr_keys()
    records = load_records()

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
