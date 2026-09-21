"""Simple client: generate a Schnorr key pair, sign a message and send it."""

import hashlib
import json
import secrets
import socket

HOST = "127.0.0.1"
PORT = 65432

# Small educational Schnorr group: q divides p-1 and g has order q.
P = 23
Q = 11
G = 2


def challenge(message, commitment, q):
    data = message + str(commitment).encode()
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q


def generate_keys():
    private_key = secrets.randbelow(Q - 1) + 1
    public_key = {
        "p": P,
        "q": Q,
        "g": G,
        "y": pow(G, private_key, P)
    }
    return private_key, public_key


def schnorr_sign(message, private_key, public_key):
    p = public_key["p"]
    q = public_key["q"]
    g = public_key["g"]

    random_nonce = secrets.randbelow(q - 1) + 1
    commitment = pow(g, random_nonce, p)
    e = challenge(message, commitment, q)
    s = (random_nonce + e * private_key) % q

    return {
        "challenge": e,
        "response": s
    }


def receive_all(connection):
    pieces = []
    while True:
        piece = connection.recv(4096)
        if not piece:
            return b"".join(pieces)
        pieces.append(piece)


def start_client():
    print("[CLIENT] Generating Schnorr key pair...")
    private_key, public_key = generate_keys()

    message_text = input("Message: ") or "Client payload for Schnorr signature test"
    message_bytes = message_text.encode("utf-8")
    signature = schnorr_sign(message_bytes, private_key, public_key)

    sent_message = message_text
    if input("Tamper message after signing? (y/n): ").lower() == "y":
        sent_message += "X"

    payload = {
        "message": sent_message,
        "signature": signature,
        "public_key": public_key
    }

    with socket.create_connection((HOST, PORT)) as client_socket:
        print("[CLIENT] Sending message, Schnorr signature and public key...")
        client_socket.sendall(json.dumps(payload).encode("utf-8"))
        client_socket.shutdown(socket.SHUT_WR)
        response = receive_all(client_socket).decode("utf-8")

    print("\n[SERVER RESPONSE]:", response)


if __name__ == "__main__":
    start_client()
