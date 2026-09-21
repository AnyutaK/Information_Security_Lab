"""
MASTER RBAC TEMPLATE

Change only these constants to adapt most exam questions:
  SYMMETRIC_ALGORITHM: "AES" or "DES"
  SIGNATURE_ALGORITHM: "RSA" or "ELGAMAL"
  ROLE_NAMES: creator, receiver, auditor names

Flow: file -> CBC encrypt -> SHA-256(ciphertext) -> sign -> store -> verify -> decrypt.
"""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from math import gcd
from pathlib import Path
from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

SYMMETRIC_ALGORITHM = "AES"       # Change to "DES" when required
SIGNATURE_ALGORITHM = "RSA"       # Change to "ELGAMAL" when required
ROLE_NAMES = ("Patient", "Doctor", "Auditor")

BASE = Path(__file__).resolve().parent / "secure_records_data"
RECORDS_FILE = BASE / "records.json"
PRIVATE_KEY_FILE = BASE / "creator_private.pem"
PUBLIC_KEY_FILE = BASE / "creator_public.pem"

# RFC 3526 MODP group used for an educational ElGamal signature implementation.
ELGAMAL_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
ELGAMAL_G = 2
ELGAMAL_KEYS_FILE = BASE / "elgamal_keys.json"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_records():
    if not RECORDS_FILE.exists():
        return []
    return json.loads(RECORDS_FILE.read_text())


def save_records(records):
    RECORDS_FILE.write_text(json.dumps(records, indent=2))


def ensure_rsa_keys():
    if not PRIVATE_KEY_FILE.exists():
        private = RSA.generate(2048)
        PRIVATE_KEY_FILE.write_bytes(private.export_key())
        PUBLIC_KEY_FILE.write_bytes(private.publickey().export_key())
        os.chmod(PRIVATE_KEY_FILE, 0o600)


def get_rsa_public():
    ensure_rsa_keys()
    return RSA.import_key(PUBLIC_KEY_FILE.read_bytes())


def get_rsa_private():
    ensure_rsa_keys()
    return RSA.import_key(PRIVATE_KEY_FILE.read_bytes())


def get_elgamal_keys():
    if not ELGAMAL_KEYS_FILE.exists():
        private = secrets.randbelow(ELGAMAL_P - 3) + 2
        data = {"p": str(ELGAMAL_P), "g": ELGAMAL_G,
                "y": str(pow(ELGAMAL_G, private, ELGAMAL_P)), "x": str(private)}
        ELGAMAL_KEYS_FILE.write_text(json.dumps(data))
        os.chmod(ELGAMAL_KEYS_FILE, 0o600)
    data = json.loads(ELGAMAL_KEYS_FILE.read_text())
    return (int(data["p"]), data["g"], int(data["y"])), int(data["x"])


def symmetric_parameters():
    if SYMMETRIC_ALGORITHM == "AES":
        return AES, 16, 16
    return DES, 8, 8


def read_exact(prompt, size):
    value = input(f"{prompt} (exactly {size} ASCII characters): ").encode()
    if len(value) != size:
        raise ValueError(f"Must be exactly {size} bytes")
    return value


def encrypt_cbc(plaintext, key, iv):
    module, _, _ = symmetric_parameters()
    return module.new(key, module.MODE_CBC, iv=iv).encrypt(pad(plaintext, module.block_size))


def decrypt_cbc(ciphertext, key, iv):
    module, _, _ = symmetric_parameters()
    return unpad(module.new(key, module.MODE_CBC, iv=iv).decrypt(ciphertext), module.block_size)


def sign_ciphertext(ciphertext):
    if SIGNATURE_ALGORITHM == "RSA":
        private = get_rsa_private()
        return {"algorithm": "RSA", "value": base64.b64encode(
            pkcs1_15.new(private).sign(SHA256.new(ciphertext))).decode()}
    public, private = get_elgamal_keys()
    p, g, _ = public
    digest = int.from_bytes(hashlib.sha256(ciphertext).digest(), "big")
    while True:
        k = secrets.randbelow(p - 3) + 2
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((digest - private * r) * pow(k, -1, p - 1)) % (p - 1)
    return {"algorithm": "ELGAMAL", "r": str(r), "s": str(s)}


def verify_signature(ciphertext, signature):
    if signature["algorithm"] == "RSA":
        public = get_rsa_public()
        try:
            pkcs1_15.new(public).verify(SHA256.new(ciphertext), base64.b64decode(signature["value"]))
            return True
        except (ValueError, TypeError):
            return False
    p, g, y = get_elgamal_keys()[0]
    r, s = int(signature["r"]), int(signature["s"])
    if not (0 < r < p and 0 < s < p - 1):
        return False
    digest = int.from_bytes(hashlib.sha256(ciphertext).digest(), "big")
    return pow(g, digest, p) == pow(y, r, p) * pow(r, s, p) % p


def choose_record(records):
    if not records:
        print("No records available."); return None
    for record in records:
        print(f'{record["id"]}: {record["filename"]} | {record["timestamp"]}')
    wanted = input("Record ID: ")
    return next((r for r in records if r["id"] == wanted), None)


def upload_record(records):
    path = Path(input("Path of .txt file: ").strip())
    if path.suffix.lower() != ".txt" or not path.is_file():
        return print("A valid .txt file is required.")
    module, key_size, iv_size = symmetric_parameters()
    try:
        key = read_exact(f"{SYMMETRIC_ALGORITHM} key", key_size)
        iv = read_exact("CBC IV", iv_size)
    except ValueError as error:
        return print("Error:", error)
    ciphertext = encrypt_cbc(path.read_bytes(), key, iv)
    digest = hashlib.sha256(ciphertext).hexdigest()
    record = {
        "id": str(len(records) + 1), "filename": path.name,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(), "sha256": digest,
        "signature": sign_ciphertext(ciphertext), "timestamp": now(),
        "verifications": []
    }
    records.append(record); save_records(records)
    print("Uploaded record", record["id"])
    print("Ciphertext (Base64):", record["ciphertext"])
    print("SHA-256:", digest)
    print("Signature:", record["signature"])


def list_creator(records):
    for record in records:
        print(json.dumps(record, indent=2))


def verify_record(record):
    ciphertext = base64.b64decode(record["ciphertext"])
    integrity = hashlib.sha256(ciphertext).hexdigest() == record["sha256"]
    authentic = verify_signature(ciphertext, record["signature"])
    return ciphertext, integrity, authentic


def receiver_verify(records, allow_decrypt=True):
    record = choose_record(records)
    if not record:
        return print("Record not found.")
    ciphertext, integrity, authentic = verify_record(record)
    result = {"timestamp": now(), "integrity": integrity, "signature": authentic}
    record["verifications"].append(result); save_records(records)
    print("Integrity:", "VALID" if integrity else "FAILED")
    print("Signature:", "VALID" if authentic else "INVALID")
    if not (integrity and authentic):
        return print("Decryption denied: record may be altered or unauthenticated.")
    if allow_decrypt:
        _, key_size, _ = symmetric_parameters()
        try:
            key = read_exact(f"Shared {SYMMETRIC_ALGORITHM} key", key_size)
            plaintext = decrypt_cbc(ciphertext, key, base64.b64decode(record["iv"]))
            print("Decrypted record:\n" + plaintext.decode())
        except (ValueError, UnicodeDecodeError) as error:
            print("Decryption failed (wrong key or damaged data):", error)


def auditor_view(records):
    for record in records:
        print({"id": record["id"], "filename": record["filename"],
               "sha256": record["sha256"], "signature": record["signature"],
               "timestamp": record["timestamp"]})
    if records and input("Verify a signature? (y/n): ").lower() == "y":
        record = choose_record(records)
        if record:
            ciphertext = base64.b64decode(record["ciphertext"])
            print("Signature:", "VALID" if verify_signature(ciphertext, record["signature"]) else "INVALID")


def tamper_record(records):
    record = choose_record(records)
    if not record:
        return
    data = bytearray(base64.b64decode(record["ciphertext"]))
    data[0] ^= 1
    record["ciphertext"] = base64.b64encode(data).decode()
    save_records(records)
    print("One ciphertext byte modified. Verification will now fail.")


def role_menu(role, records):
    creator, receiver, auditor = ROLE_NAMES
    if role == creator:
        while True:
            choice = input("\n1 Upload  2 View records  3 Verify/decrypt  4 Tamper demo  0 Back: ")
            if choice == "1": upload_record(records)
            elif choice == "2": list_creator(records)
            elif choice == "3": receiver_verify(records)
            elif choice == "4": tamper_record(records)
            elif choice == "0": return
    elif role == receiver:
        while True:
            choice = input("\n1 View available  2 Verify/decrypt  0 Back: ")
            if choice == "1": choose_record(records)
            elif choice == "2": receiver_verify(records)
            elif choice == "0": return
    else:
        auditor_view(records)


def main():
    BASE.mkdir(exist_ok=True)
    records = load_records()
    while True:
        print(f"\n=== SECURE RECORDS: {SYMMETRIC_ALGORITHM}-CBC + {SIGNATURE_ALGORITHM} ===")
        for index, role in enumerate(ROLE_NAMES, 1): print(index, role)
        print("0 Exit")
        choice = input("Role: ")
        if choice == "0": break
        if choice in ("1", "2", "3"): role_menu(ROLE_NAMES[int(choice) - 1], records)
        else: print("Invalid choice")


if __name__ == "__main__":
    main()
