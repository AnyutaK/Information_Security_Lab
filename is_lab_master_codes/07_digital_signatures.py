"""Lab 6: RSA, ElGamal and Schnorr digital signatures."""

import hashlib
import secrets
from math import gcd
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# RFC 3526 1536-bit MODP prime; g=2. Fine for a lab demonstration.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
G = 2


def rsa_generate():
    private = RSA.generate(2048)
    return private.publickey(), private


def rsa_sign(message, private):
    return pkcs1_15.new(private).sign(SHA256.new(message))


def rsa_verify(message, signature, public):
    try:
        pkcs1_15.new(public).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


def elgamal_generate():
    x = secrets.randbelow(P - 3) + 2
    return (P, G, pow(G, x, P)), x


def elgamal_sign(message, private, public):
    p, g, _ = public
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        k = secrets.randbelow(p - 3) + 2
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((digest - private * r) * pow(k, -1, p - 1)) % (p - 1)
    return r, s


def elgamal_verify(message, signature, public):
    p, g, y = public
    r, s = signature
    if not (0 < r < p and 0 < s < p - 1):
        return False
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return pow(g, digest, p) == (pow(y, r, p) * pow(r, s, p)) % p


# Schnorr over a small educational subgroup where p=23, q=11 and g has order q.
def schnorr_generate(p=23, q=11, g=2):
    x = secrets.randbelow(q - 1) + 1
    return (p, q, g, pow(g, x, p)), x


def schnorr_sign(message, private, public):
    p, q, g, _ = public
    k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p)
    challenge = int.from_bytes(hashlib.sha256(message + str(r).encode()).digest(), "big") % q
    return challenge, (k + challenge * private) % q


def schnorr_verify(message, signature, public):
    p, q, g, y = public
    challenge, s = signature
    r_check = pow(g, s, p) * pow(pow(y, challenge, p), -1, p) % p
    expected = int.from_bytes(hashlib.sha256(message + str(r_check).encode()).digest(), "big") % q
    return expected == challenge


if __name__ == "__main__":
    message = input("Message: ").encode()
    algorithm = input("RSA / ELGAMAL / SCHNORR: ").upper()
    if algorithm == "RSA":
        public, private = rsa_generate(); signature = rsa_sign(message, private)
        verify = lambda data: rsa_verify(data, signature, public)
        shown = signature.hex()
    elif algorithm == "ELGAMAL":
        public, private = elgamal_generate(); signature = elgamal_sign(message, private, public)
        verify = lambda data: elgamal_verify(data, signature, public)
        shown = signature
    else:
        public, private = schnorr_generate(); signature = schnorr_sign(message, private, public)
        verify = lambda data: schnorr_verify(data, signature, public)
        shown = signature
    print("Signature:", shown)
    print("Original verification:", "VALID" if verify(message) else "INVALID")
    print("Tampered verification:", "VALID" if verify(message + b"X") else "INVALID")
