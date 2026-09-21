"""ElGamal server: publish key, receive ciphertext pairs and decrypt message."""

import hashlib
import json
import secrets
import socket

HOST, PORT = "127.0.0.1", 5102
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


def decrypt(ciphertext, private_key):
    recovered = []
    for c1, c2 in ciphertext:
        shared = pow(c1, private_key, P)
        recovered.append(c2 * pow(shared, -1, P) % P)
    return bytes(recovered)


def main():
    private_key = secrets.randbelow(P - 3) + 2
    public_value = pow(G, private_key, P)

    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[ELGAMAL SERVER] Listening on {HOST}:{PORT}")
        connection, address = server.accept()

        with connection:
            print("[ELGAMAL SERVER] Connected:", address)
            send_json(connection, {"p": P, "g": G, "y": public_value})
            request = receive_json(connection)
            plaintext = decrypt(request["ciphertext"], private_key)
            integrity_valid = hashlib.sha256(plaintext).hexdigest() == request["sha256"]

            if integrity_valid:
                response = "ELGAMAL DECRYPTED: " + plaintext.decode()
            else:
                response = "INTEGRITY FAILED"

            print("[ELGAMAL SERVER]", response)
            send_json(connection, {"result": response})


if __name__ == "__main__":
    main()

