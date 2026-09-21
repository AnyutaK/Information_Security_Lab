"""Server: verify SHA-256 and Schnorr before AES/DES decryption."""

import base64
import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad


# These settings must match the client.
SYMMETRIC_ALGORITHM = "AES"  # "AES" or "DES"
AES_KEY_SIZE = 16             # 16, 24 or 32
HOST = "127.0.0.1"
PORT = 5003

PUBLIC_FILE = Path("schnorr_client_public.json")
LOG_FILE = Path("schnorr_server_verifications.json")


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


def schnorr_verify(data, signature):
    if not PUBLIC_FILE.exists():
        raise FileNotFoundError("Run schnorr_socket_keygen.py first")

    public = json.loads(PUBLIC_FILE.read_text())
    p, q, g, y = public["p"], public["q"], public["g"], public["y"]
    e, s = signature["challenge"], signature["response"]

    if not (0 <= e < q and 0 <= s < q):
        return False

    reconstructed = (
        pow(g, s, p) * pow(pow(y, e, p), -1, p)
    ) % p
    return challenge(data, reconstructed, q) == e


def receive_all(connection):
    pieces = []
    while True:
        piece = connection.recv(4096)
        if not piece:
            return b"".join(pieces)
        pieces.append(piece)


def save_verification(result):
    history = json.loads(LOG_FILE.read_text()) if LOG_FILE.exists() else []
    history.append(result)
    LOG_FILE.write_text(json.dumps(history, indent=2))


def main():
    if not PUBLIC_FILE.exists():
        print("Run schnorr_socket_keygen.py before starting the server")
        return

    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"Schnorr secure server listening on {HOST}:{PORT}")

        connection, address = server.accept()
        with connection:
            request = json.loads(receive_all(connection).decode())
            ciphertext = base64.b64decode(request["ciphertext"])
            iv = base64.b64decode(request["iv"])

            settings_match = (
                request["algorithm"] == SYMMETRIC_ALGORITHM
                and request["aes_key_size"] == AES_KEY_SIZE
            )
            integrity_valid = hashlib.sha256(ciphertext).hexdigest() == request["sha256"]
            signature_valid = schnorr_verify(
                ciphertext, request["schnorr_signature"]
            )

            result = {
                "client": str(address),
                "filename": request["filename"],
                "settings_match": settings_match,
                "integrity": integrity_valid,
                "schnorr_signature": signature_valid,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")
            }
            save_verification(result)

            print("Settings:", "MATCH" if settings_match else "MISMATCH")
            print("Integrity:", "VALID" if integrity_valid else "FAILED")
            print("Schnorr signature:", "VALID" if signature_valid else "INVALID")

            if not (settings_match and integrity_valid and signature_valid):
                response = "VERIFICATION FAILED; DECRYPTION DENIED"
            else:
                try:
                    key = read_key()
                    module, key_size, iv_size = symmetric_parameters()
                    plaintext = unpad(
                        module.new(key, module.MODE_CBC, iv).decrypt(ciphertext),
                        module.block_size
                    )
                    response = "VERIFIED\nRecovered plaintext:\n" + plaintext.decode()
                    print(response)
                except (ValueError, UnicodeDecodeError) as error:
                    response = "DECRYPTION FAILED: incorrect key or damaged data"
                    print(error)

            connection.sendall(response.encode())


if __name__ == "__main__":
    main()
