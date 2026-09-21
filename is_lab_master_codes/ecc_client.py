"""ECC client: derive ECDH key and send AES-GCM-encrypted message."""

import hashlib
import json
import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC

HOST, PORT = "127.0.0.1", 5101


def send_json(connection, value):
    data = json.dumps(value).encode()
    connection.sendall(len(data).to_bytes(4, "big") + data)


def receive_exact(connection, size):
    data = b""
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise ConnectionError("Connection closed")
        data += part
    return data


def receive_json(connection):
    size = int.from_bytes(receive_exact(connection, 4), "big")
    return json.loads(receive_exact(connection, size).decode())


def derive_key(private_key, peer_public_key):
    point = peer_public_key.pointQ * int(private_key.d)
    return hashlib.sha256(int(point.x).to_bytes(32, "big")).digest()


def main():
    with socket.create_connection((HOST, PORT)) as client:
        server_data = receive_json(client)
        server_public = ECC.import_key(server_data["server_public_key"])
        client_private = ECC.generate(curve="P-256")
        aes_key = derive_key(client_private, server_public)

        plaintext = input("Message: ").encode()
        encryptor = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = encryptor.encrypt_and_digest(plaintext)

        if input("Tamper ciphertext? (y/n): ").lower() == "y":
            changed = bytearray(ciphertext)
            changed[0] ^= 1
            ciphertext = bytes(changed)

        send_json(
            client,
            {
                "client_public_key": client_private.public_key().export_key(format="PEM"),
                "nonce": encryptor.nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex()
            }
        )
        print("[SERVER RESPONSE]", receive_json(client)["result"])


if __name__ == "__main__":
    main()
