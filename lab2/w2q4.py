from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
message = input("Enter message: ").encode()
key = input("Enter Triple DES key (24 characters): ").encode()
if len(key) != 48:
    print("Error: Triple DES key must be exactly 24 bytes.")
    exit()
iv = get_random_bytes(8)
cipher = DES3.new(key, DES3.MODE_CBC, iv)
padded_message = pad(message, DES3.block_size)
ciphertext = cipher.encrypt(padded_message)
print("\nEncrypted ciphertext:", ciphertext.hex())
print("IV:", iv.hex())
cipher = DES3.new(key, DES3.MODE_CBC, iv)
decrypted_padded = cipher.decrypt(ciphertext)
decrypted_message = unpad(
    decrypted_padded,
    DES3.block_size
)
print("Decrypted message:", decrypted_message.decode())
if decrypted_message == message:
    print("Verification: Successful")
else:
    print("Verification: Failed")