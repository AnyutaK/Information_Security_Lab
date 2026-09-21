"""Lab 5 server: receive one or many Base64 parts and return SHA-256."""

import base64
import hashlib
import json
import socket

HOST, PORT = "127.0.0.1", 5000

with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Hash server listening on {HOST}:{PORT}")
    connection, address = server.accept()
    with connection:
        request = json.loads(connection.recv(1_000_000).decode())
        message = b"".join(base64.b64decode(part) for part in request["parts"])
        digest = hashlib.sha256(message).hexdigest()
        connection.sendall(json.dumps({"sha256": digest}).encode())
        print("Received from", address, "message:", message.decode(errors="replace"))
        print("Returned hash:", digest)
