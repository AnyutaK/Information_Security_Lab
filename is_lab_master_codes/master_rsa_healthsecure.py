"""RSA-only HealthSecure template with Doctor/Nurse/Admin RBAC."""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

BASE = Path(__file__).resolve().parent / "healthsecure_data"
PRIVATE = BASE / "doctor_private.pem"
PUBLIC = BASE / "doctor_public.pem"
RECORDS = BASE / "records.json"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_keys():
    BASE.mkdir(exist_ok=True)
    if not PRIVATE.exists():
        key = RSA.generate(2048)
        PRIVATE.write_bytes(key.export_key()); PUBLIC.write_bytes(key.publickey().export_key())
        os.chmod(PRIVATE, 0o600)


def public_key():
    ensure_keys()
    return RSA.import_key(PUBLIC.read_bytes())


def private_key():
    ensure_keys()
    return RSA.import_key(PRIVATE.read_bytes())


def load():
    return json.loads(RECORDS.read_text()) if RECORDS.exists() else []


def save(records):
    RECORDS.write_text(json.dumps(records, indent=2))


def rsa_encrypt_chunks(data, public):
    # RSA-2048 OAEP-SHA256 accepts at most 190 bytes per block.
    cipher = PKCS1_OAEP.new(public, hashAlgo=SHA256)
    return [cipher.encrypt(data[i:i + 190]) for i in range(0, len(data), 190)]


def rsa_decrypt_chunks(chunks, private):
    cipher = PKCS1_OAEP.new(private, hashAlgo=SHA256)
    return b"".join(cipher.decrypt(chunk) for chunk in chunks)


def flattened(chunks):
    return b"".join(chunks)


def enter_record(records):
    patient = {
        "name": input("Name: "), "age": input("Age: "), "gender": input("Gender: "),
        "blood_group": input("Blood group: "), "diagnosis": input("Diagnosis: "),
        "other_details": input("Other medical details: ")
    }
    public, private = public_key(), private_key()
    chunks = rsa_encrypt_chunks(json.dumps(patient).encode(), public)
    encrypted = flattened(chunks)
    digest = hashlib.sha256(encrypted).hexdigest()
    signature = pkcs1_15.new(private).sign(SHA256.new(encrypted))
    record = {
        "id": str(len(records) + 1), "patient_name": patient["name"],
        "chunks": [base64.b64encode(c).decode() for c in chunks], "sha256": digest,
        "signature": base64.b64encode(signature).decode(), "timestamp": now(),
        "verifications": []
    }
    records.append(record); save(records)
    print("Stored encrypted record", record["id"])


def list_records(records, role):
    for r in records:
        common = {"id": r["id"], "name": r["patient_name"], "sha256": r["sha256"],
                  "timestamp": r["timestamp"]}
        if role in ("Doctor", "Nurse"):
            common.update({"encrypted_data": r["chunks"], "signature": r["signature"]})
        print(json.dumps(common, indent=2))


def choose(records):
    wanted = input("Record ID: ")
    return next((r for r in records if r["id"] == wanted), None)


def verify(record):
    public = public_key()
    chunks = [base64.b64decode(c) for c in record["chunks"]]
    encrypted = flattened(chunks)
    integrity = hashlib.sha256(encrypted).hexdigest() == record["sha256"]
    try:
        pkcs1_15.new(public).verify(SHA256.new(encrypted), base64.b64decode(record["signature"]))
        authentic = True
    except (ValueError, TypeError):
        authentic = False
    return chunks, integrity, authentic


def verify_selected(records, role):
    record = choose(records)
    if not record:
        return print("Record not found")
    chunks, integrity, authentic = verify(record)
    result = {"role": role, "integrity": integrity, "signature": authentic, "timestamp": now()}
    record["verifications"].append(result); save(records)
    if role != "Admin": print("Integrity:", "VALID" if integrity else "FAILED")
    print("Signature:", "VALID" if authentic else "INVALID")
    if role == "Doctor":
        if integrity and authentic:
            private = private_key()
            print("Patient information:", rsa_decrypt_chunks(chunks, private).decode())
        else:
            print("Decryption denied.")


def menu(role, records):
    while True:
        if role == "Doctor": prompt = "1 Add  2 View  3 Verify/decrypt  0 Back: "
        elif role == "Nurse": prompt = "1 View encrypted records  2 Verify  0 Back: "
        else: prompt = "1 View metadata  2 Verify signature  0 Back: "
        choice = input(prompt)
        if choice == "0": return
        if role == "Doctor" and choice == "1": enter_record(records)
        elif role == "Doctor" and choice == "2": list_records(records, role)
        elif role == "Doctor" and choice == "3": verify_selected(records, role)
        elif role in ("Nurse", "Admin") and choice == "1": list_records(records, role)
        elif role in ("Nurse", "Admin") and choice == "2": verify_selected(records, role)
        else: print("Unauthorized/invalid operation")


def main():
    ensure_keys(); records = load()
    while True:
        choice = input("\n1 Doctor  2 Nurse  3 Admin  0 Exit: ")
        if choice == "0": break
        roles = {"1": "Doctor", "2": "Nurse", "3": "Admin"}
        if choice in roles: menu(roles[choice], records)


if __name__ == "__main__":
    main()
