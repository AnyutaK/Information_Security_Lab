
import math
def generate_keypair():
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    # Choose e such that gcd(e, phi) = 1
    e = 17
    # Calculate d, the modular inverse of e
    d = pow(e, -1, phi)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key
def encrypt(public_key, message):
    e, n = public_key
    # RSA encryption: c = m^e mod n
    ciphertext = pow(message, e, n)
    return ciphertext
def decrypt(private_key, ciphertext):
    d, n = private_key
    # RSA decryption: m = c^d mod n
    message = pow(ciphertext, d, n)
    return message
def homomorphic_multiply(ciphertext1, ciphertext2, public_key):
    e, n = public_key
    # E(m1) * E(m2) mod n = E(m1 * m2)
    ciphertext_product = (ciphertext1 * ciphertext2) % n
    return ciphertext_product
a = int(input("Enter first integer: "))
b = int(input("Enter second integer: "))
public_key, private_key = generate_keypair()
ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)
ciphertext_product = homomorphic_multiply(ciphertext_a,ciphertext_b,public_key)
decrypted_product = decrypt(private_key,ciphertext_product)
print("\nRSA Multiplicative Homomorphic Encryption")
print("First integer:", a)
print("Ciphertext of first integer:", ciphertext_a)
print("\nSecond integer:", b)
print("Ciphertext of second integer:", ciphertext_b)
print("\nCiphertext of encrypted multiplication:", ciphertext_product)
print("\nDecrypted product:", decrypted_product)
print("Expected product:", a * b)
if decrypted_product == a * b:
    print("Verification: SUCCESS")
else:
    print("Verification: FAILED")
