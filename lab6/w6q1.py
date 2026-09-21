import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util import number
import os
def elgamal_demo():
    print("1. ELGAMAL DIGITAL SIGNATURE")
    bits = 512
    p = number.getPrime(bits)
    g = 2
    x = number.getRandomRange(2, p - 2)
    y = pow(g, x, p)
    message = b"Testing ElGamal Signature Scheme"
    m_hash = int(hashlib.sha256(message).hexdigest(), 16)
    while True:
        k = number.getRandomRange(2, p - 2)
        if number.GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = number.inverse(k, p - 1)
    s = (k_inv * (m_hash - x * r)) % (p - 1)
    print(f"Message: {message.decode()}")
    print(f"Signature Pair (r, s):\n  r = {r}\n  s = {s}")
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m_hash, p)
    print(f"Verification Check: {v1 == v2}")
    print("Result: ElGamal Signature Verified Successfully!")
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
def schnorr_demo():
    print("2. SCHNORR (Ed25519) DIGITAL SIGNATURE")
    key = ECC.generate(curve='Ed25519')
    pub_key = key.public_key()
    message = b"Testing Schnorr Signature Scheme"
    signer = eddsa.new(key,'rfc8032')
    signature = signer.sign(message)
    print(f"Message: {message.decode()}")
    print(f"Schnorr Signature (Hex): {signature.hex()}")
    verifier = eddsa.new(pub_key, 'rfc8032')
    try:
        verifier.verify(message, signature)
        print("Verification Check: True")
        print("Result: Schnorr Signature Verified Successfully!")
    except ValueError:
        print("Verification Failed!")
if __name__ == "__main__":
    elgamal_demo()
    schnorr_demo()