"""ECIES-style file encryption: ephemeral P-256 ECDH plus AES-256-GCM."""

import hashlib
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC


def derive_key(private_key, public_key):
    point = public_key.pointQ * int(private_key.d)
    return hashlib.sha256(int(point.x).to_bytes(32, "big")).digest()


def main():
    path = Path(input("Input .txt file: ").strip())
    if path.suffix.lower() != ".txt" or not path.is_file():
        print("Valid .txt file required")
        return

    recipient_private = ECC.generate(curve="P-256")
    recipient_public = recipient_private.public_key()
    ephemeral_private = ECC.generate(curve="P-256")
    ephemeral_public = ephemeral_private.public_key()

    sender_key = derive_key(ephemeral_private, recipient_public)
    encryptor = AES.new(sender_key, AES.MODE_GCM)
    ciphertext, tag = encryptor.encrypt_and_digest(path.read_bytes())

    receiver_key = derive_key(recipient_private, ephemeral_public)
    recovered = AES.new(receiver_key, AES.MODE_GCM, nonce=encryptor.nonce).decrypt_and_verify(ciphertext, tag)

    print("Ephemeral public key:\n", ephemeral_public.export_key(format="PEM"))
    print("Ciphertext:", ciphertext.hex())
    print("Nonce:", encryptor.nonce.hex())
    print("Tag:", tag.hex())
    print("Recovered content:\n" + recovered.decode())


if __name__ == "__main__":
    main()
