import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(1)
    print("[SERVER] Listening on 127.0.0.1:65432...")
    conn, addr = server_socket.accept()
    print(f"[SERVER] Connection established from {addr}")
    data = conn.recv(4096).decode('utf-8')
    payload = json.loads(data)
    message = payload['message'].encode('utf-8')
    signature = bytes.fromhex(payload['signature'])
    pub_key_pem = payload['public_key']
    print("\n[SERVER] Received Transmission:")
    print(f"  Message: {payload['message']}")
    print(f"  Signature (truncated): {payload['signature'][:30]}...")
    pub_key = RSA.import_key(pub_key_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        response = "VERIFICATION SUCCESSFUL: Signature is valid and payload is authentic."
        print(f"[SERVER] {response}")
    except (ValueError, TypeError):
        response = "VERIFICATION FAILED: Signature is invalid or payload was tampered with!"
        print(f"[SERVER] {response}")
    conn.sendall(response.encode('utf-8'))
    conn.close()
if __name__ == "__main__":
    start_server()