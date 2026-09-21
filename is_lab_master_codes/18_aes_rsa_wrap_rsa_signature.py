"""AES data encryption + recipient RSA key wrapping + sender RSA signature."""

import hashlib
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


def main():
    path = Path(input("Input .txt file: ").strip())
    if path.suffix.lower() != ".txt" or not path.is_file():
        print("Valid .txt file required")
        return

    # Separate identities: recipient decrypts the AES key; sender signs the ciphertext.
    recipient_private = RSA.generate(2048)
    recipient_public = recipient_private.publickey()
    sender_private = RSA.generate(2048)
    sender_public = sender_private.publickey()

    aes_key, iv = get_random_bytes(16), get_random_bytes(16)
    ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(path.read_bytes(), 16))
    stored_hash = hashlib.sha256(ciphertext).hexdigest()
    wrapped_key = PKCS1_OAEP.new(recipient_public, hashAlgo=SHA256).encrypt(aes_key)
    signature = pkcs1_15.new(sender_private).sign(SHA256.new(ciphertext))

    receiver_hash = hashlib.sha256(ciphertext).hexdigest()
    integrity_valid = receiver_hash == stored_hash
    try:
        pkcs1_15.new(sender_public).verify(SHA256.new(ciphertext), signature)
        signature_valid = True
    except (ValueError, TypeError):
        signature_valid = False

    print("Ciphertext:", ciphertext.hex())
    print("Wrapped AES key:", wrapped_key.hex())
    print("SHA-256:", stored_hash)
    print("RSA signature:", signature.hex())
    print("Integrity:", "VALID" if integrity_valid else "FAILED")
    print("Signature:", "VALID" if signature_valid else "INVALID")

    if integrity_valid and signature_valid:
        recovered_key = PKCS1_OAEP.new(recipient_private, hashAlgo=SHA256).decrypt(wrapped_key)
        plaintext = unpad(AES.new(recovered_key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
        print("Recovered AES key:", recovered_key.hex())
        print("Recovered content:\n" + plaintext.decode())
    else:
        print("Decryption denied")


if __name__ == "__main__":
    main()

