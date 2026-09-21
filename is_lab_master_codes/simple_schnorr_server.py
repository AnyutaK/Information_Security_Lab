"""Simple server: receive a message and verify its Schnorr signature."""

import hashlib
import json
import socket

HOST = "127.0.0.1"
PORT = 65432


def challenge(message, commitment, q):
    data = message + str(commitment).encode()
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q


def schnorr_verify(message, signature, public_key):
    p = public_key["p"]
    q = public_key["q"]
    g = public_key["g"]
    y = public_key["y"]
    e = signature["challenge"]
    s = signature["response"]

    if not (0 <= e < q and 0 <= s < q):
        return False

    # For s = k + e*x, recover r as g^s * (y^e)^(-1) mod p.
    reconstructed_commitment = (
        pow(g, s, p)
        * pow(pow(y, e, p), -1, p)
    ) % p

    expected_challenge = challenge(
        message,
        reconstructed_commitment,
        q
    )

    return expected_challenge == e


def receive_all(connection):
    pieces = []
    while True:
        piece = connection.recv(4096)
        if not piece:
            return b"".join(pieces)
        pieces.append(piece)


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT}...")

        connection, address = server_socket.accept()

        with connection:
            print(f"[SERVER] Connection established from {address}")
            payload = json.loads(receive_all(connection).decode("utf-8"))
            message = payload["message"].encode("utf-8")
            signature = payload["signature"]
            public_key = payload["public_key"]

            print("\n[SERVER] Received Transmission:")
            print("  Message:", payload["message"])
            print("  Schnorr signature:", signature)
            print("  Schnorr public key:", public_key)

            if schnorr_verify(message, signature, public_key):
                response = "VERIFICATION SUCCESSFUL: Schnorr signature is valid."
            else:
                response = "VERIFICATION FAILED: Schnorr signature is invalid or data was tampered with."

            print("[SERVER]", response)
            connection.sendall(response.encode("utf-8"))


if __name__ == "__main__":
    start_server()

