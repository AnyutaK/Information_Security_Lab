import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
def start_client():
    print("[CLIENT] Generating RSA Key Pair...")
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    message_text = "Client payload for digital signature test"
    message_bytes = message_text.encode('utf-8')
    h = SHA256.new(message_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    payload = {
        'message': message_text,
        'signature': signature.hex(),
        'public_key': public_key.export_key().decode('utf-8')
    }
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65432))
    print("[CLIENT] Sending message, signature, and public key to server...")
    client_socket.sendall(json.dumps(payload).encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(f"\n[SERVER RESPONSE]: {response}")
    client_socket.close()
if __name__ == "__main__":
    start_client()