"""Labs 3-4: RSA, ElGamal, Rabin, ECC hybrid encryption and Diffie-Hellman."""

import base64
import hashlib
import secrets
from math import gcd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse


# ---------- Textbook RSA (small-number educational demonstration) ----------
def rsa_toy_keys(p=61, q=53, e=17):
    n, phi = p * q, (p - 1) * (q - 1)
    return (n, e), (n, pow(e, -1, phi))


def rsa_toy_encrypt(text, public_key):
    n, e = public_key
    return [pow(byte, e, n) for byte in text.encode()]


def rsa_toy_decrypt(ciphertext, private_key):
    n, d = private_key
    return bytes(pow(value, d, n) for value in ciphertext).decode()


# ---------- Practical RSA-OAEP ----------
def rsa_oaep_demo(message):
    key = RSA.generate(2048)
    encrypted = PKCS1_OAEP.new(key.publickey()).encrypt(message.encode())
    decrypted = PKCS1_OAEP.new(key).decrypt(encrypted).decode()
    return key.publickey().export_key().decode(), encrypted, decrypted


# ---------- ElGamal encryption (each byte is encrypted independently) ----------
def elgamal_keys(p=7919, g=2, private=2999):
    return (p, g, pow(g, private, p)), private


def elgamal_encrypt(text, public_key):
    p, g, y = public_key
    output = []
    for byte in text.encode():
        k = secrets.randbelow(p - 3) + 2
        output.append((pow(g, k, p), byte * pow(y, k, p) % p))
    return output


def elgamal_decrypt(ciphertext, private_key, p):
    values = []
    for c1, c2 in ciphertext:
        shared = pow(c1, private_key, p)
        values.append(c2 * pow(shared, -1, p) % p)
    return bytes(values).decode()


# ---------- Rabin cryptosystem (four possible roots per block) ----------
def rabin_keys(bits=256):
    def blum_prime():
        while True:
            value = getPrime(bits)
            if value % 4 == 3:
                return value
    p, q = blum_prime(), blum_prime()
    return p * q, (p, q)


def rabin_encrypt_number(message_number, public_n):
    if not 0 <= message_number < public_n:
        raise ValueError("Message number must be smaller than n")
    return pow(message_number, 2, public_n)


def rabin_decrypt_roots(ciphertext, private_key):
    p, q = private_key
    n = p * q
    mp, mq = pow(ciphertext, (p + 1) // 4, p), pow(ciphertext, (q + 1) // 4, q)
    yp, yq = inverse(p, q), inverse(q, p)
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    return (r1, r2, r3, n - r3)


# ---------- ECC: ECDH shared secret + AES-GCM data encryption ----------
def ecc_hybrid_encrypt(plaintext, recipient_public_key):
    ephemeral = ECC.generate(curve="P-256")
    shared_point = recipient_public_key.pointQ * int(ephemeral.d)
    aes_key = hashlib.sha256(int(shared_point.x).to_bytes(32, "big")).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return ephemeral.public_key().export_key(format="PEM"), cipher.nonce, ciphertext, tag


def ecc_hybrid_decrypt(package, recipient_private_key):
    ephemeral_pem, nonce, ciphertext, tag = package
    ephemeral_public = ECC.import_key(ephemeral_pem)
    shared_point = ephemeral_public.pointQ * int(recipient_private_key.d)
    aes_key = hashlib.sha256(int(shared_point.x).to_bytes(32, "big")).digest()
    return AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag).decode()


# ---------- Diffie-Hellman ----------
def diffie_hellman(p=23, g=5):
    alice_private, bob_private = secrets.randbelow(p - 3) + 2, secrets.randbelow(p - 3) + 2
    alice_public, bob_public = pow(g, alice_private, p), pow(g, bob_private, p)
    alice_secret = pow(bob_public, alice_private, p)
    bob_secret = pow(alice_public, bob_private, p)
    return alice_public, bob_public, alice_secret, bob_secret


def main():
    message = input("Message: ")
    print("1 RSA toy  2 RSA-OAEP  3 ElGamal  4 Rabin(number)  5 ECC hybrid  6 Diffie-Hellman")
    choice = input("Choice: ")
    if choice == "1":
        pub, priv = rsa_toy_keys(); c = rsa_toy_encrypt(message, pub)
        print("Public:", pub, "Private:", priv, "Cipher:", c, "Plain:", rsa_toy_decrypt(c, priv))
    elif choice == "2":
        pub, c, plain = rsa_oaep_demo(message)
        print(pub); print("Cipher (Base64):", base64.b64encode(c).decode()); print("Plain:", plain)
    elif choice == "3":
        pub, priv = elgamal_keys(); c = elgamal_encrypt(message, pub)
        print("Public:", pub, "Private:", priv, "Cipher:", c, "Plain:", elgamal_decrypt(c, priv, pub[0]))
    elif choice == "4":
        number = int(message); public, private = rabin_keys(); c = rabin_encrypt_number(number, public)
        print("n:", public, "Cipher:", c, "Four roots:", rabin_decrypt_roots(c, private))
    elif choice == "5":
        key = ECC.generate(curve="P-256"); package = ecc_hybrid_encrypt(message, key.public_key())
        print("Cipher (Base64):", base64.b64encode(package[2]).decode())
        print("Plain:", ecc_hybrid_decrypt(package, key))
    elif choice == "6":
        a, b, sa, sb = diffie_hellman(); print("Public values:", a, b, "Shared secrets:", sa, sb)


if __name__ == "__main__":
    main()
