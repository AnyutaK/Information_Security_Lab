"""Lab 6 server: receive a message, RSA public key and signature; verify authenticity."""

import base64
import json
import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

HOST, PORT = "127.0.0.1", 5001

with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT)); server.listen(1)
    print(f"Signature server listening on {HOST}:{PORT}")
    connection, _ = server.accept()
    with connection:
        request = json.loads(connection.recv(1_000_000).decode())
        message = base64.b64decode(request["message"])
        signature = base64.b64decode(request["signature"])
        public = RSA.import_key(request["public_key"])
        try:
            pkcs1_15.new(public).verify(SHA256.new(message), signature)
            result = "VALID"
        except (ValueError, TypeError):
            result = "INVALID"
        connection.sendall(json.dumps({"signature": result}).encode())
        print("Signature:", result)
