"""Classical Diffie-Hellman key exchange followed by AES-128-CBC."""

import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Educational public parameters. Use standardized large groups in real applications.
P = 7919
G = 2


def derive_aes_key(shared_secret):
    raw = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8 or 1, "big")
    return hashlib.sha256(raw).digest()[:16]


def main():
    alice_private = secrets.randbelow(P - 3) + 2
    bob_private = secrets.randbelow(P - 3) + 2

    alice_public = pow(G, alice_private, P)
    bob_public = pow(G, bob_private, P)

    alice_shared = pow(bob_public, alice_private, P)
    bob_shared = pow(alice_public, bob_private, P)

    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared secret:", alice_shared)
    print("Bob shared secret:", bob_shared)
    print("Shared secrets match:", alice_shared == bob_shared)

    aes_key = derive_aes_key(alice_shared)
    iv = get_random_bytes(16)
    plaintext = input("Message: ").encode()
    ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    recovered = unpad(AES.new(derive_aes_key(bob_shared), AES.MODE_CBC, iv).decrypt(ciphertext), 16)

    print("Derived AES key:", aes_key.hex())
    print("IV:", iv.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered plaintext:", recovered.decode())


if __name__ == "__main__":
    main()

