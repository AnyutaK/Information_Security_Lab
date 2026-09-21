"""DH server: exchange public values, derive AES key, verify hash and decrypt."""

import hashlib
import json
import secrets
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST, PORT = "127.0.0.1", 5104
P, G = 7919, 2


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
    server_private = secrets.randbelow(P - 3) + 2
    server_public = pow(G, server_private, P)

    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[DH SERVER] Listening on {HOST}:{PORT}")
        connection, address = server.accept()

        with connection:
            print("[DH SERVER] Connected:", address)
            send_json(connection, {"p": P, "g": G, "server_public": server_public})
            request = receive_json(connection)

            shared_secret = pow(request["client_public"], server_private, P)
            aes_key = derive_key(shared_secret)
            ciphertext = bytes.fromhex(request["ciphertext"])
            integrity_valid = hashlib.sha256(ciphertext).hexdigest() == request["sha256"]

            if integrity_valid:
                try:
                    plaintext = unpad(
                        AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(request["iv"])).decrypt(ciphertext),
                        16
                    )
                    response = "DH/AES VERIFIED: " + plaintext.decode()
                except (ValueError, UnicodeDecodeError):
                    response = "DECRYPTION FAILED"
            else:
                response = "INTEGRITY FAILED; DECRYPTION DENIED"

            print("Shared secret:", shared_secret)
            print("[DH SERVER]", response)
            send_json(connection, {"result": response})


if __name__ == "__main__":
    main()

