import socket,hashlib
host="127.0.0.1"
port=5000
server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket.bind((host,port))
server_socket.listen(1)
print(f"server is listening on {host}:{port}")
conn,addr=server_socket.accept()
print("connected by:",addr)
data=conn.recv(4096)
print("received data:",data.decode())
hash_value=hashlib.sha256(data).hexdigest()
print(f"hash value computer by server: {hash_value}")
conn.sendall(hash_value.encode())
conn.close()
server_socket.close()
'''
output:
python3 W5Q2S.py
server is listening on 127.0.0.1:5000
connected by: ('127.0.0.1', 52218)
received data: this is a secret message in IS lab
hash value computer by server: 92dafdcfdf32549a07bd7fb8f7e6a75fd188e97acc1fde49dec63d07bfc83ebe
'''