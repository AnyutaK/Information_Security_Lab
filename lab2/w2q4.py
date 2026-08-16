from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

message = input("Enter message: ").encode()
key = input("Enter Triple DES key (48 characters): ").encode()
if len(key) != 48:
    print("Error: Triple DES key must be exactly 48 characters.")
    exit()
key = key[:24]
cipher = DES3.new(key, DES3.MODE_ECB)
padded_message = pad(message, DES3.block_size)
ciphertext = cipher.encrypt(padded_message)
print("\nEncrypted ciphertext:", ciphertext.hex())
cipher = DES3.new(key, DES3.MODE_ECB)
decrypted_padded = cipher.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded, DES3.block_size)
print("Decrypted message:", decrypted_message.decode())
if decrypted_message == message:
    print("Verification: Successful")
else:
    print("Verification: Failed")