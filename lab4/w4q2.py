import os
import json
import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
class RabinKeyManager:
    def __init__(
        self,
        key_size=1024,
        storage_file="healthcare_keys.json",
        audit_file="key_audit.log"
    ):
        self.key_size = key_size
        self.storage_file = storage_file
        self.audit_file = audit_file
        self.records: Dict[str, dict] = {}
        logging.basicConfig(
            filename=self.audit_file,
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s"
        )
        self.load_keys()
    def log_event(self, operation, facility, details=""):
        logging.info("Operation=%s | Facility=%s | Details=%s",
            operation,facility,details )
    def is_prime(self, n):
        if n < 2:
            return False
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19,23, 29, 31, 37]
        for p in small_primes:
            if n % p == 0:
                return n == p
        d = n - 1
        r = 0
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(40):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    def generate_prime(self, bits):
        while True:
            p = secrets.randbits(bits)
            p |= (1 << (bits - 1))
            p |= 3
            if p % 4 == 3 and self.is_prime(p):
                return p
    def generate_rabin_keys(self):
        half = self.key_size // 2
        p = self.generate_prime(half)
        q = self.generate_prime(half)
        while q == p:
            q = self.generate_prime(half)
        n = p * q
        return {"public_key": {"n": n},"private_key": {"p": p,"q": q} }
    def derive_storage_key(self):
        master_key = "HealthCareIncSecureMasterKey2026"
        return hashlib.sha256(master_key.encode() ).digest()
    def encrypt_private_key(self, private_key):
        key = self.derive_storage_key()
        nonce = os.urandom(12)
        plaintext = json.dumps(
            private_key
        ).encode()
        ciphertext = AESGCM(key).encrypt(
            nonce,
            plaintext,
            None
        )
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext
            ).decode()}
    def decrypt_private_key(self, encrypted_key):
        key = self.derive_storage_key()
        nonce = base64.b64decode( encrypted_key["nonce"])
        ciphertext = base64.b64decode(encrypted_key["ciphertext"])
        plaintext = AESGCM(key).decrypt( nonce,ciphertext,None)
        return json.loads(plaintext.decode())
    def save_keys(self):
        temporary_file = self.storage_file + ".tmp"
        with open( temporary_file, "w") as file:
            json.dump( self.records,file,indent=4 )
        os.replace(temporary_file,self.storage_file)
    def load_keys(self):
        if not os.path.exists(self.storage_file ):
            self.records = {}
            return
        try:
            with open( self.storage_file,
                "r"
            ) as file:
                self.records = json.load(file)
        except json.JSONDecodeError:
            self.records = {}
    def register_facility(self, facility_id):
        if facility_id in self.records:
            raise ValueError( "Facility already registered." )
        keys = self.generate_rabin_keys()
        encrypted_private_key = ( self.encrypt_private_key(
                keys["private_key"]))
        now = datetime.now( timezone.utc )
        self.records[facility_id] = {
            "public_key": keys["public_key"],
            "private_key": encrypted_private_key,
            "created_at": now.isoformat(),
            "expires_at": (
                now + timedelta(days=365)
            ).isoformat(),
            "status": "ACTIVE",
            "version": 1
        }
        self.save_keys()
        self.log_event("KEY_GENERATION", facility_id,
            "Initial Rabin key pair generated."  )
        print( f"Key generated for {facility_id}")
    def get_keys(self, facility_id):
        if facility_id not in self.records:
            raise ValueError(
                "Facility not found."
            )
        record = self.records[
            facility_id
        ]
        if record["status"] != "ACTIVE":
            raise PermissionError(
                "Facility key is not active."
            )
        private_key = (
            self.decrypt_private_key(
                record["private_key"]
            )
        )
        self.log_event(
            "KEY_DISTRIBUTION",
            facility_id,
            f"Version {record['version']} distributed."
        )
        return {
            "public_key": record["public_key"],
            "private_key": private_key,
            "version": record["version"],
            "expires_at": record["expires_at"]
        }
    def revoke_key(self, facility_id):
        if facility_id not in self.records:
            raise ValueError( "Facility not found.")
        self.records[
            facility_id
        ]["status"] = "REVOKED"
        self.save_keys()
        self.log_event(
            "KEY_REVOCATION",
            facility_id,
            "Key revoked."
        )
        print( f"Key revoked for {facility_id}" )
    def renew_key(self, facility_id):
        if facility_id not in self.records:
            raise ValueError( "Facility not found.")
        keys = self.generate_rabin_keys()
        encrypted_private_key = (
            self.encrypt_private_key(
                keys["private_key"]
            )
        )
        now = datetime.now( timezone.utc)
        old_version = (
            self.records[facility_id]["version"])
        self.records[facility_id] = {
            "public_key": keys["public_key"],
            "private_key": encrypted_private_key,
            "created_at": now.isoformat(),
            "expires_at": (
                now + timedelta(days=365)
            ).isoformat(),
            "status": "ACTIVE",
            "version": old_version + 1
        }
        self.save_keys()
        self.log_event(
            "KEY_RENEWAL",
            facility_id,
            f"New version {old_version + 1} generated."
        )
        print(f"Key renewed for {facility_id}")
    def renew_expired_keys(self):
        now = datetime.now(timezone.utc)
        for facility_id, record in list(
            self.records.items()
        ):
            expires_at = datetime.fromisoformat(record["expires_at"])
            if expires_at <= now and record["status"] == "ACTIVE":
                self.renew_key( facility_id )
    def get_status(self, facility_id):
        if facility_id not in self.records:
            raise ValueError( "Facility not found." )
        record = self.records[facility_id]
        return {
            "facility": facility_id,
            "status": record["status"],
            "version": record["version"],
            "created_at": record["created_at"],
            "expires_at": record["expires_at"]
        }
def rabin_encrypt(message, public_key):
    n = public_key["n"]
    message_bytes = message.encode()
    prefix = b"HC01"
    data = (prefix+ len(message_bytes).to_bytes(4,"big")+ message_bytes )
    m = int.from_bytes(data,"big")
    if m >= n:
        raise ValueError("Message is too large for the Rabin key.")
    return pow(m,2,n)
def rabin_decrypt(
    ciphertext,
    private_key
):
    p = private_key["p"]
    q = private_key["q"]
    n = p * q
    yp = pow(q,-1, p)
    yq = pow(p,-1,q)
    mp = pow(ciphertext,(p + 1) // 4,p)
    mq = pow(ciphertext,(q + 1) // 4,q)
    r1 = (yp * q * mp+ yq * p * mq) % n
    r2 = n - r1
    r3 = (yp * q * mp- yq * p * mq) % n
    r4 = n - r3
    candidates = [r1,r2,r3,r4]
    for candidate in candidates:
        size = max(1,(candidate.bit_length() + 7) // 8)
        data = candidate.to_bytes(size,"big")
        if (
            data.startswith(b"HC01")
            and len(data) >= 8
        ):
            length = int.from_bytes(data[4:8],"big")
            message = data[8:]
            if len(message) == length:
                return message.decode()
    raise ValueError("Unable to determine the correct plaintext.")
def main():
    print("HealthCare Inc. Centralized Rabin Key Management Service")
    service = RabinKeyManager(
        key_size=1024,
        storage_file="healthcare_keys.json",
        audit_file="key_audit.log")
    for facility in ["Hospital-A","Hospital-B","Clinic-C"]:
        if facility not in service.records:
            service.register_facility(facility)
    hospital_a = service.get_keys("Hospital-A")
    print("Hospital-A Public Key:")
    print(hospital_a["public_key"])
    message = "Confidential Patient Record"
    encrypted = rabin_encrypt(message,hospital_a["public_key"])
    print("Encrypted Data:")
    print(encrypted)
    decrypted = rabin_decrypt(encrypted,hospital_a["private_key"])
    print("Decrypted Data:")
    print(decrypted)
    print("Hospital-A Status:")
    print(service.get_status("Hospital-A"))
    print("Revoking Hospital-B key...")
    service.revoke_key("Hospital-B" )
    print(service.get_status("Hospital-B"))
    print("Renewing Hospital-A key...")
    service.renew_key("Hospital-A")
    print(service.get_status("Hospital-A"))
    print("Checking automatic key renewal...")
    service.renew_expired_keys()
    print("Audit log saved to:",service.audit_file)
    print("Encrypted key storage saved to:",service.storage_file)
if __name__ == "__main__":
    main()