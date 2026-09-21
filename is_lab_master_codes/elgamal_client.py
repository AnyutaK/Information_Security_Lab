"""ElGamal client: receive server public key, encrypt and send message."""

import hashlib
import json
import secrets
import socket

HOST, PORT = "127.0.0.1", 5102


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


def encrypt(data, public_key):
    p, g, y = public_key
    ciphertext = []
    for byte in data:
        k = secrets.randbelow(p - 3) + 2
        ciphertext.append([pow(g, k, p), byte * pow(y, k, p) % p])
    return ciphertext


def main():
    with socket.create_connection((HOST, PORT)) as client:
        public = receive_json(client)
        public_key = (public["p"], public["g"], public["y"])
        plaintext = input("Message: ").encode()
        ciphertext = encrypt(plaintext, public_key)

        if input("Tamper ciphertext? (y/n): ").lower() == "y":
            ciphertext[0][1] = (ciphertext[0][1] + 1) % public["p"]

        send_json(
            client,
            {
                "ciphertext": ciphertext,
                "sha256": hashlib.sha256(plaintext).hexdigest()
            }
        )
        print("Public key:", public_key)
        print("Ciphertext pairs:", ciphertext)
        print("[SERVER RESPONSE]", receive_json(client)["result"])


if __name__ == "__main__":
    main()
