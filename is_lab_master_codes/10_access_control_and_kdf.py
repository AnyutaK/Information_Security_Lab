"""Lab 4 helpers: KDF, RBAC, ABAC, DAC, MAC/Bell-LaPadula and time access."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone


def derive_key(password, salt=None, iterations=200_000, length=32):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=length)
    return key, salt


RBAC_PERMISSIONS = {
    "creator": {"encrypt", "view_ciphertext", "view_hash"},
    "receiver": {"view_ciphertext", "verify", "decrypt"},
    "auditor": {"view_hash", "verify_signature"},
}


def rbac_allowed(role, operation):
    return operation in RBAC_PERMISSIONS.get(role, set())


def abac_allowed(user, record, environment):
    return (user.get("department") == record.get("department") and
            user.get("clearance", 0) >= record.get("classification", 0) and
            environment.get("trusted_device", False))


def bell_lapadula_read(subject_level, object_level):
    return subject_level >= object_level  # no read up


def bell_lapadula_write(subject_level, object_level):
    return subject_level <= object_level  # no write down


def discretionary_access(access_matrix, subject, object_name, right):
    return right in access_matrix.get(subject, {}).get(object_name, set())


def time_access(start, end, current=None):
    current = current or datetime.now(timezone.utc)
    return start <= current <= end


if __name__ == "__main__":
    key, salt = derive_key(input("Password for PBKDF2: "))
    print("Salt:", salt.hex())
    print("Derived AES-256 key:", key.hex())
    for role in RBAC_PERMISSIONS:
        print(role, "can decrypt:", rbac_allowed(role, "decrypt"))
    start = datetime.now(timezone.utc)
    print("One-hour access valid:", time_access(start, start + timedelta(hours=1)))
