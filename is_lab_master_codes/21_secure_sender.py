"""Socket sender: AES-CBC encryption, SHA-256 and RSA signature."""

import base64
import hashlib
import json
import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad

HOST, PORT = "127.0.0.1", 5002
SHARED_AES_KEY = b"1234567890123456"


def main():
    plaintext = input("Message: ").encode()
    private_key = RSA.generate(2048)
    iv = get_random_bytes(16)
    ciphertext = AES.new(SHARED_AES_KEY, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    stored_hash = hashlib.sha256(ciphertext).hexdigest()
    signature = pkcs1_15.new(private_key).sign(SHA256.new(ciphertext))

    transmitted = ciphertext
    if input("Tamper before sending? (y/n): ").lower() == "y":
        changed = bytearray(ciphertext)
        changed[0] ^= 1
        transmitted = bytes(changed)

    request = {
        "ciphertext": base64.b64encode(transmitted).decode(),
        "iv": base64.b64encode(iv).decode(),
        "hash": stored_hash,
        "signature": base64.b64encode(signature).decode(),
        "public_key": private_key.publickey().export_key().decode(),
    }

    with socket.create_connection((HOST, PORT)) as client:
        client.sendall(json.dumps(request).encode())
        client.shutdown(socket.SHUT_WR)
        response = client.recv(4096).decode()
    print("Receiver response:", response)


if __name__ == "__main__":
    main()

