from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
def show_bytes(label, data):
    print(f"\n{label}:")
    print(base64.b64encode(data).decode())
class KeyManager:
    def __init__(self):
        self.systems = {}
        self.revoked_systems = set()
    def register_system(self, system):
        self.systems[system.name] = system
        print(f"[KeyManager] Registered: {system.name}")
    def revoke_system(self, system_name):
        if system_name in self.systems:
            self.revoked_systems.add(system_name)
            print(f"[KeyManager] Key revoked: {system_name}")
    def is_revoked(self, system_name):
        return system_name in self.revoked_systems
class Subsystem:
    def __init__(self, name, dh_parameters):
        self.name = name
        self.dh_parameters = dh_parameters
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.dh_private_key = dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        print(f"\n[{self.name}] RSA and DH keys generated.")
    def display_rsa_keys(self):
        private_bytes = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"RSA KEYS - {self.name}")
        print("RSA PRIVATE KEY:")
        print(private_bytes.decode())
        print("RSA PUBLIC KEY:")
        print(public_bytes.decode())
    def create_shared_key(self, other_dh_public_key):
        shared_secret = self.dh_private_key.exchange(
            other_dh_public_key
        )
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureCorp AES Key"
        ).derive(shared_secret)
        return shared_secret, aes_key
    def sign_document(self, document):
        signature = self.rsa_private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    def verify_signature(
        self,
        document,
        signature,
        sender_public_key
    ):
        try:
            sender_public_key.verify(
                signature,
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    def encrypt_document(self, document, aes_key):
        aes = AESGCM(aes_key)
        nonce = os.urandom(12)
        encrypted_document = aes.encrypt(
            nonce,
            document,
            None
        )
        return nonce, encrypted_document
    def decrypt_document(
        self,
        nonce,
        encrypted_document,
        aes_key
    ):
        aes = AESGCM(aes_key)
        document = aes.decrypt(
            nonce,
            encrypted_document,
            None
        )
        return document
print("SECURECORP SECURE COMMUNICATION")
print("Generating Diffie-Hellman parameters...")
dh_parameters = dh.generate_parameters(
    generator=2,
    key_size=2048
)
print("DH parameters generated successfully.")
key_manager = KeyManager()
finance = Subsystem(
    "Finance System (A)",
    dh_parameters
)
hr = Subsystem(
    "HR System (B)",
    dh_parameters
)
supply_chain = Subsystem(
    "Supply Chain System (C)",
    dh_parameters
)
print("KEY MANAGEMENT")
key_manager.register_system(finance)
key_manager.register_system(hr)
key_manager.register_system(supply_chain)
finance.display_rsa_keys()
hr.display_rsa_keys()
print("FINANCE SYSTEM -> HR SYSTEM")
print("[STEP 1] DIFFIE-HELLMAN KEY EXCHANGE")
print("Finance sends its DH public key to HR.")
print("HR sends its DH public key to Finance.")
finance_secret, finance_aes_key = finance.create_shared_key(
    hr.dh_public_key
)
hr_secret, hr_aes_key = hr.create_shared_key(
    finance.dh_public_key
)
show_bytes(
    "Finance DH Shared Secret",
    finance_secret
)
show_bytes(
    "HR DH Shared Secret",
    hr_secret
)
print("Are the shared secrets equal?")
print(finance_secret == hr_secret)
print("[STEP 2] AES KEY GENERATION")
show_bytes(
    "Finance AES-256 Key",
    finance_aes_key
)
show_bytes(
    "HR AES-256 Key",
    hr_aes_key
)
print("Are the AES keys equal?")
print(finance_aes_key == hr_aes_key)
print("[STEP 3] ORIGINAL DOCUMENT")
document = (
    b"Financial Report: SecureCorp Revenue = $5,000,000"
)
print(document.decode())
print("[STEP 4] RSA DIGITAL SIGNATURE")
signature = finance.sign_document(document)
show_bytes(
    "RSA Digital Signature",
    signature
)
print("[STEP 5] AES ENCRYPTION")
nonce, encrypted_document = finance.encrypt_document(
    document,
    finance_aes_key
)
show_bytes(
    "AES Nonce",
    nonce
)
show_bytes(
    "Encrypted Document",
    encrypted_document
)
print("HR RECEIVES DATA")
print("[STEP 6] AES DECRYPTION")
decrypted_document = hr.decrypt_document(
    nonce,
    encrypted_document,
    hr_aes_key
)
print("Decrypted Document:")
print(decrypted_document.decode())
print("[STEP 7] RSA SIGNATURE VERIFICATION")
result = hr.verify_signature(
    decrypted_document,
    signature,
    finance.rsa_public_key
)
print("Signature valid?")
print(result)
print(" KEY REVOCATION")
key_manager.revoke_system(
    supply_chain.name
)
print(
    "Is Supply Chain System revoked?",
    key_manager.is_revoked(supply_chain.name)
)
print("SCALABILITY")
new_system = Subsystem(
    "New Procurement System (D)",
    dh_parameters
)
key_manager.register_system(new_system)
print("New subsystem added successfully.")
print("PROGRAM COMPLETED")
