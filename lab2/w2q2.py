from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
msg = input("Enter message: ").encode()
key_input = input("Enter AES-128 key (32 characters): ")
if len(key) != 32:
    print("Error: AES-128 key must be exactly 32 characters.")
    exit()
key = bytes.fromhex(key_input)
iv = os.urandom(16)
pad = padding.PKCS7(algorithms.AES.block_size).padder()
pm = pad.update(msg) + pad.finalize()
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ct = encryptor.update(pm) + encryptor.finalize()
print("\nEncrypted ciphertext:", ct.hex())
print("IV:", iv.hex())
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
ppt = decryptor.update(ct) + decryptor.finalize()
unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
pt = unpad.update(ppt) + unpad.finalize()
print("Decrypted message:", pt.decode())
if pt == msg:
    print("Verification: Successful")
else:
    print("Verification: Failed")