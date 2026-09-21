"""P-256 ECDH key exchange followed by AES-256-GCM."""

import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC


def derive_key(private_key, peer_public_key):
    shared_point = peer_public_key.pointQ * int(private_key.d)
    x_coordinate = int(shared_point.x).to_bytes(32, "big")
    return hashlib.sha256(x_coordinate).digest()


def main():
    alice_private = ECC.generate(curve="P-256")
    bob_private = ECC.generate(curve="P-256")
    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    alice_key = derive_key(alice_private, bob_public)
    bob_key = derive_key(bob_private, alice_public)
    print("Derived keys match:", alice_key == bob_key)

    plaintext = input("Message: ").encode()
    encryptor = AES.new(alice_key, AES.MODE_GCM)
    ciphertext, tag = encryptor.encrypt_and_digest(plaintext)

    decryptor = AES.new(bob_key, AES.MODE_GCM, nonce=encryptor.nonce)
    recovered = decryptor.decrypt_and_verify(ciphertext, tag)

    print("Alice public key:\n", alice_public.export_key(format="PEM"))
    print("Bob public key:\n", bob_public.export_key(format="PEM"))
    print("Nonce:", encryptor.nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Authentication tag:", tag.hex())
    print("Recovered plaintext:", recovered.decode())


if __name__ == "__main__":
    main()

