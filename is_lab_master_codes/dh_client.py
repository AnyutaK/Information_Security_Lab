"""DH client: exchange public values, derive AES key and send encrypted message."""

import hashlib
import json
import secrets
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

HOST, PORT = "127.0.0.1", 5104


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


def derive_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]


def main():
    with socket.create_connection((HOST, PORT)) as client:
        server_data = receive_json(client)
        p, g = server_data["p"], server_data["g"]
        server_public = server_data["server_public"]
        client_private = secrets.randbelow(p - 3) + 2
        client_public = pow(g, client_private, p)
        shared_secret = pow(server_public, client_private, p)
        aes_key = derive_key(shared_secret)

        plaintext = input("Message: ").encode()
        iv = get_random_bytes(16)
        ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
        stored_hash = hashlib.sha256(ciphertext).hexdigest()

        if input("Tamper ciphertext? (y/n): ").lower() == "y":
            changed = bytearray(ciphertext)
            changed[0] ^= 1
            ciphertext = bytes(changed)

        send_json(
            client,
            {
                "client_public": client_public,
                "iv": iv.hex(),
                "ciphertext": ciphertext.hex(),
                "sha256": stored_hash
            }
        )
        print("Client public value:", client_public)
        print("Shared secret:", shared_secret)
        print("[SERVER RESPONSE]", receive_json(client)["result"])


if __name__ == "__main__":
    main()
