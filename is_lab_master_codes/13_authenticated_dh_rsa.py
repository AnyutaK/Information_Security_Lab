"""Authenticate Diffie-Hellman public values using RSA signatures."""

import secrets
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

P = 7919
G = 2


def sign_public_value(value, private_key):
    data = str(value).encode()
    return pkcs1_15.new(private_key).sign(SHA256.new(data))


def verify_public_value(value, signature, public_key):
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(str(value).encode()), signature)
        return True
    except (ValueError, TypeError):
        return False


def main():
    alice_rsa = RSA.generate(2048)
    bob_rsa = RSA.generate(2048)
    alice_private = secrets.randbelow(P - 3) + 2
    bob_private = secrets.randbelow(P - 3) + 2
    alice_public = pow(G, alice_private, P)
    bob_public = pow(G, bob_private, P)

    alice_signature = sign_public_value(alice_public, alice_rsa)
    bob_signature = sign_public_value(bob_public, bob_rsa)
    alice_valid = verify_public_value(alice_public, alice_signature, alice_rsa.publickey())
    bob_valid = verify_public_value(bob_public, bob_signature, bob_rsa.publickey())

    print("Alice DH signature:", "VALID" if alice_valid else "INVALID")
    print("Bob DH signature:", "VALID" if bob_valid else "INVALID")
    if not (alice_valid and bob_valid):
        print("Key exchange rejected")
        return

    alice_shared = pow(bob_public, alice_private, P)
    bob_shared = pow(alice_public, bob_private, P)
    print("Authenticated shared secret:", alice_shared)
    print("Secrets match:", alice_shared == bob_shared)


if __name__ == "__main__":
    main()
