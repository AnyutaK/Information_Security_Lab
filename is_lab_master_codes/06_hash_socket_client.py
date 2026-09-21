"""Lab 5 client: send multipart data and compare local/server SHA-256 hashes."""

import base64
import hashlib
import json
import socket

HOST, PORT = "127.0.0.1", 5000
message = input("Message: ").encode()
mid = len(message) // 2
parts = [message[:mid], message[mid:]]

if input("Tamper before transmission? (y/n): ").lower() == "y" and parts:
    parts[-1] += b"X"

request = {"parts": [base64.b64encode(part).decode() for part in parts]}
with socket.create_connection((HOST, PORT)) as client:
    client.sendall(json.dumps(request).encode())
    response = json.loads(client.recv(4096).decode())

local_hash = hashlib.sha256(message).hexdigest()
print("Local hash: ", local_hash)
print("Server hash:", response["sha256"])
print("Integrity:", "VALID" if local_hash == response["sha256"] else "FAILED - data changed")
