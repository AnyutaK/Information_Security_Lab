from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
import hashlib, hmac
def diffie_hellman_authenticated_message():
    print("DIFFIE-HELLMAN KEY EXCHANGE & AUTHENTICATION")
    alice_key = ECC.generate(curve='p256')
    bob_key = ECC.generate(curve='p256')
    alice_pub = alice_key.public_key()
    bob_pub = bob_key.public_key()
    alice_shared = alice_key.d * bob_pub.pointQ
    alice_derived_key = hashlib.sha256(str(alice_shared.x).encode()).digest()
    bob_shared = bob_key.d * alice_pub.pointQ
    bob_derived_key = hashlib.sha256(str(bob_shared.x).encode()).digest()
    assert alice_derived_key == bob_derived_key
    print("DH Shared Key successfully established between Alice & Bob!")
    print("CRITICAL OBSERVATION FOR LAB REPORT")
    print("Diffie-Hellman cannot natively create an asymmetric digital signature.")
    print("Instead, DH relies on establishing a SHARED SECRET, which is then used")
    print("with an HMAC (or combined with DSA) to authenticate data integrity.")
    message = b"Authentic payload signed via DH Shared Secret"
    tag = hmac.new(bob_derived_key, message, hashlib.sha256).hexdigest()
    print(f"Message: {message.decode()}")
    print(f"HMAC Tag: {tag}")
if __name__ == "__main__":
    diffie_hellman_authenticated_message()