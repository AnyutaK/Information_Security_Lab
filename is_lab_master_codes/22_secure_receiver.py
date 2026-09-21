"""Socket receiver: verify SHA-256 and RSA signature before AES decryption."""

import base64
import hashlib
import json
import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad

HOST, PORT = "127.0.0.1", 5002
SHARED_AES_KEY = b"1234567890123456"


def receive_all(connection):
    pieces = []
    while True:
        piece = connection.recv(4096)
        if not piece:
            return b"".join(pieces)
        pieces.append(piece)


def main():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"Secure receiver listening on {HOST}:{PORT}")
        connection, address = server.accept()
        with connection:
            request = json.loads(receive_all(connection).decode())
            ciphertext = base64.b64decode(request["ciphertext"])
            iv = base64.b64decode(request["iv"])
            integrity_valid = hashlib.sha256(ciphertext).hexdigest() == request["hash"]

            try:
                public_key = RSA.import_key(request["public_key"])
                signature = base64.b64decode(request["signature"])
                pkcs1_15.new(public_key).verify(SHA256.new(ciphertext), signature)
                signature_valid = True
            except (ValueError, TypeError):
                signature_valid = False

            print("Connected:", address)
            print("Integrity:", "VALID" if integrity_valid else "FAILED")
            print("Signature:", "VALID" if signature_valid else "INVALID")

            if integrity_valid and signature_valid:
                plaintext = unpad(AES.new(SHARED_AES_KEY, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
                result = "VERIFIED: " + plaintext.decode()
            else:
                result = "VERIFICATION FAILED; DECRYPTION DENIED"
            connection.sendall(result.encode())


if __name__ == "__main__":
    main()

