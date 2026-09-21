"""Client: AES/DES encrypt, SHA-256 hash, Schnorr sign and transmit."""

import base64
import hashlib
import json
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


# These settings must match the server.
SYMMETRIC_ALGORITHM = "AES"  # "AES" or "DES"
AES_KEY_SIZE = 16             # 16, 24 or 32
HOST = "127.0.0.1"
PORT = 5003

PRIVATE_FILE = Path("schnorr_client_private.json")
PUBLIC_FILE = Path("schnorr_client_public.json")


def symmetric_parameters():
    if SYMMETRIC_ALGORITHM == "AES":
        if AES_KEY_SIZE not in (16, 24, 32):
            raise ValueError("AES key size must be 16, 24 or 32")
        return AES, AES_KEY_SIZE, 16
    if SYMMETRIC_ALGORITHM == "DES":
        return DES, 8, 8
    raise ValueError("Use AES or DES")


def read_key():
    module, key_size, iv_size = symmetric_parameters()
    key = input(f"Enter the shared {key_size}-character key: ").encode()
    if len(key) != key_size:
        raise ValueError(f"Key must be exactly {key_size} bytes")
    return key


def challenge(data, commitment, q):
    return int.from_bytes(
        hashlib.sha256(data + str(commitment).encode()).digest(), "big"
    ) % q


def schnorr_sign(data):
    if not PRIVATE_FILE.exists() or not PUBLIC_FILE.exists():
        raise FileNotFoundError("Run schnorr_socket_keygen.py first")

    private_key = json.loads(PRIVATE_FILE.read_text())["x"]
    public = json.loads(PUBLIC_FILE.read_text())
    p, q, g = public["p"], public["q"], public["g"]

    nonce = secrets.randbelow(q - 1) + 1
    commitment = pow(g, nonce, p)
    e = challenge(data, commitment, q)
    s = (nonce + e * private_key) % q
    return {"challenge": e, "response": s}


def receive_all(connection):
    pieces = []
    while True:
        piece = connection.recv(4096)
        if not piece:
            return b"".join(pieces)
        pieces.append(piece)


def main():
    path = Path(input("Enter .txt filename: ").strip())
    if path.suffix.lower() != ".txt" or not path.is_file():
        print("A valid .txt file is required")
        return

    try:
        key = read_key()
    except ValueError as error:
        print(error)
        return

    module, key_size, iv_size = symmetric_parameters()
    iv = get_random_bytes(iv_size)
    ciphertext = module.new(key, module.MODE_CBC, iv).encrypt(
        pad(path.read_bytes(), module.block_size)
    )
    stored_hash = hashlib.sha256(ciphertext).hexdigest()
    signature = schnorr_sign(ciphertext)

    transmitted_ciphertext = ciphertext
    if input("Tamper before transmission? (y/n): ").lower() == "y":
        changed = bytearray(ciphertext)
        changed[0] ^= 1
        transmitted_ciphertext = bytes(changed)

    request = {
        "filename": path.name,
        "algorithm": SYMMETRIC_ALGORITHM,
        "aes_key_size": AES_KEY_SIZE,
        "ciphertext": base64.b64encode(transmitted_ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "sha256": stored_hash,
        "schnorr_signature": signature,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")
    }

    print("Ciphertext:", request["ciphertext"])
    print("IV:", request["iv"])
    print("SHA-256:", stored_hash)
    print("Schnorr signature:", signature)

    with socket.create_connection((HOST, PORT)) as client:
        client.sendall(json.dumps(request).encode())
        client.shutdown(socket.SHUT_WR)
        response = receive_all(client).decode()

    print("Server response:\n" + response)


if __name__ == "__main__":
    main()

