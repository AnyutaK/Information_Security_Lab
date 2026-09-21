"""Lab 6 client: sign a message with RSA and send it for verification."""

import base64
import json
import socket
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

HOST, PORT = "127.0.0.1", 5001
private = RSA.generate(2048)
message = input("Message: ").encode()
signature = pkcs1_15.new(private).sign(SHA256.new(message))
sent_message = message + (b"X" if input("Tamper message? (y/n): ").lower() == "y" else b"")
request = {
    "message": base64.b64encode(sent_message).decode(),
    "signature": base64.b64encode(signature).decode(),
    "public_key": private.publickey().export_key().decode(),
}
with socket.create_connection((HOST, PORT)) as client:
    client.sendall(json.dumps(request).encode())
    print(json.loads(client.recv(4096).decode()))
