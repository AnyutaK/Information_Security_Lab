from Crypto.Cipher import AES,DES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
import time
msg=input("enter the message").encode()
des_key=input("DES key(8 characters)").encode()
aes_key=input("AES key(32 characters)").encode()
if len(aes_key) != 32:
    print("Error: AES-256 key must be exactly 32 characters.")
    exit()
if len(des_key) != 8:
    print("Error: DES key must be exactly 8 characters.")
    exit()
iters=10000
des_iv=get_random_bytes(8)
start1=time.perf_counter()
for i in range(iters):
    cipher=DES.new(des_key,DES.MODE_CBC,des_iv)
    des_ct=cipher.encrypt(pad(msg,DES.block_size))
des_enc_time=time.perf_counter()-start1
start2=time.perf_counter()
for i in range(iters):
    cipher=DES.new(des_key,DES.MODE_CBC,des_iv)
    des_pt=unpad(cipher.decrypt(des_ct),DES.block_size)
des_dec_time=time.perf_counter()-start2
aes_iv=get_random_bytes(16)
start3=time.perf_counter()
for i in range(iters):
    cipher=AES.new(aes_key,AES.MODE_CBC,aes_iv)
    aes_ct=cipher.encrypt(pad(msg,AES.block_size))
aes_enc_time=time.perf_counter()-start3
start4=time.perf_counter()
for i in range(iters):
    cipher=AES.new(aes_key,AES.MODE_CBC,aes_iv)
    aes_pt=unpad(cipher.decrypt(aes_ct),AES.block_size)
aes_dec_time=time.perf_counter()-start4
print ("Performance Results")
print ("message:",msg.decode())
print("iterations:",iters)
print("DES")
print("ciphertext:",des_ct.hex())
print("encryption time",des_enc_time,"seconds")
print("decryption time",des_dec_time,"seconds")
print("AES-256")
print("ciphertext:",aes_ct.hex())
print("encryption time",aes_enc_time,"seconds")
print("decryption time",aes_dec_time,"seconds")
print("Average times:")
print("DES Encryption",(des_enc_time/iters)*1_000_000,"microseconds")
print("DES Decryption",(des_dec_time/iters)*1_000_000,"microseconds")
print("AES Encryption",(aes_enc_time/iters)*1_000_000,"microseconds")
print("AES decryption",(aes_dec_time/iters)*1_000_000,"microseconds")
print("\nVERIFICATION")
if des_pt == msg:
    print("DES decryption: Successful")
else:
    print("DES decryption: Failed")
if aes_pt == msg:
    print("AES-256 decryption: Successful")
else:
    print("AES-256 decryption: Failed")
print("\nComparison:")
if des_enc_time < aes_enc_time:
    print("DES encryption was faster.")
else:
    print("AES-256 encryption was faster.")
if des_dec_time < aes_dec_time:
    print("DES decryption was faster.")
else:
    print("AES-256 decryption was faster.")
print("\nConclusion:")
print("For the given message and 10,000 iterations,")
print("the algorithm with the lower average time was faster.")