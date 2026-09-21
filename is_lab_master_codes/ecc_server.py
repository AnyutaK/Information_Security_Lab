"""ECC server: send P-256 public key, derive ECDH key, decrypt AES-GCM message."""

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
    server_private = ECC.generate(curve="P-256")
    server_public_pem = server_private.public_key().export_key(format="PEM")

    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[ECC SERVER] Listening on {HOST}:{PORT}")
        connection, address = server.accept()

        with connection:
            print("[ECC SERVER] Connected:", address)
            send_json(connection, {"server_public_key": server_public_pem})
            request = receive_json(connection)

            client_public = ECC.import_key(request["client_public_key"])
            aes_key = derive_key(server_private, client_public)

            try:
                decryptor = AES.new(
                    aes_key,
                    AES.MODE_GCM,
                    nonce=bytes.fromhex(request["nonce"])
                )
                plaintext = decryptor.decrypt_and_verify(
                    bytes.fromhex(request["ciphertext"]),
                    bytes.fromhex(request["tag"])
                )
                response = "ECC/ECDH VERIFIED: " + plaintext.decode()
            except ValueError:
                response = "ECC/ECDH VERIFICATION FAILED: ciphertext or tag was modified"

            print("[ECC SERVER]", response)
            send_json(connection, {"result": response})


if __name__ == "__main__":
    main()

