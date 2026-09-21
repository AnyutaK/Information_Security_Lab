"""RSA-2048 OAEP-SHA256 file encryption/decryption using safe-size chunks."""

import base64
from pathlib import Path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

CHUNK_SIZE = 190  # Maximum for RSA-2048 OAEP with SHA-256.


def encrypt_file(data, public_key):
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return [cipher.encrypt(data[i:i + CHUNK_SIZE]) for i in range(0, len(data), CHUNK_SIZE)]


def decrypt_file(chunks, private_key):
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return b"".join(cipher.decrypt(chunk) for chunk in chunks)


def main():
    path = Path(input("Input .txt file: ").strip())
    if path.suffix.lower() != ".txt" or not path.is_file():
        print("Valid .txt file required")
        return

    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    chunks = encrypt_file(path.read_bytes(), public_key)
    recovered = decrypt_file(chunks, private_key)

    print("RSA public values: n =", public_key.n, "e =", public_key.e)
    print("Encrypted chunks:")
    for number, chunk in enumerate(chunks, 1):
        print(number, base64.b64encode(chunk).decode())
    print("Recovered file content:\n" + recovered.decode())


if __name__ == "__main__":
    main()

