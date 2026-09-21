"""Sign-then-encrypt: RSA-sign plaintext, then AES-encrypt plaintext plus signature."""

from pathlib import Path
from Crypto.Cipher import AES
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

    plaintext = path.read_bytes()
    sender_private = RSA.generate(2048)
    sender_public = sender_private.publickey()
    signature = pkcs1_15.new(sender_private).sign(SHA256.new(plaintext))

    # A two-byte signature length lets the receiver split the decrypted payload.
    payload = len(signature).to_bytes(2, "big") + signature + plaintext
    aes_key, iv = get_random_bytes(16), get_random_bytes(16)
    ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(payload, 16))

    recovered_payload = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
    signature_length = int.from_bytes(recovered_payload[:2], "big")
    recovered_signature = recovered_payload[2:2 + signature_length]
    recovered_plaintext = recovered_payload[2 + signature_length:]

    try:
        pkcs1_15.new(sender_public).verify(SHA256.new(recovered_plaintext), recovered_signature)
        valid = True
    except (ValueError, TypeError):
        valid = False

    print("RSA signature:", signature.hex())
    print("AES IV:", iv.hex())
    print("Encrypted payload:", ciphertext.hex())
    print("Signature after decryption:", "VALID" if valid else "INVALID")
    if valid:
        print("Recovered content:\n" + recovered_plaintext.decode())


if __name__ == "__main__":
    main()
