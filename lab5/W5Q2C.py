import socket,hashlib
host="127.0.0.1"
port=5000
data=b"this is a secret message in IS lab"
local_hash = hashlib.sha256(data).hexdigest()
print("original_message:",data.decode())
print("Local hash:",local_hash)
client_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client_socket.connect((host,port))
client_socket.sendall(data)
server_hash=client_socket.recv(64).decode()
print("hash received from the server:",server_hash)
if server_hash==local_hash:
    print("success: data integrity verified")
    print("this data wasnt corrupted during transmission")
else:
    print("failure: data integrity check failed")
    print("this data may have been corrupted or tampered with during transmission")
client_socket.close()

'''
output :
original_message: this is a secret message in IS lab
Local hash: 92dafdcfdf32549a07bd7fb8f7e6a75fd188e97acc1fde49dec63d07bfc83ebe
hash received from the server: 92dafdcfdf32549a07bd7fb8f7e6a75fd188e97acc1fde49dec63d07bfc83ebe
success: data integrity verified
this data wasnt corrupted during transmission
'''