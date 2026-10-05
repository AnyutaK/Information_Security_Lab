import math
import random
from sympy import randprime

def generate_keypair(bits=512):
    p = randprime(2**(bits - 1), 2**bits)
    q = randprime(2**(bits - 1), 2**bits)
    while p == q:
        q = randprime(2**(bits - 1), 2**bits)
    n = p * q
    n_squared = n * n
    # lambda = lcm(p-1, q-1)
    lam = math.lcm(p - 1, q - 1)
    # Use g = n + 1
    g = n + 1
    # mu = (L(g^lambda mod n^2))^(-1) mod n
    x = pow(g, lam, n_squared)
    L = (x - 1) // n
    mu = pow(L, -1, n)
    public_key = (n, g)
    private_key = (lam, mu)
    return public_key, private_key
def encrypt(public_key, message):
    n, g = public_key
    n_squared = n * n
    # Choose random r such that gcd(r,n) = 1
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    # c = g^m * r^n mod n^2
    ciphertext = (pow(g, message, n_squared) *
                  pow(r, n, n_squared)) % n_squared
    return ciphertext
def decrypt(private_key, public_key, ciphertext):
    n, g = public_key
    lam, mu = private_key
    n_squared = n * n
    x = pow(ciphertext, lam, n_squared)
    L = (x - 1) // n
    message = (L * mu) % n
    return message
def homomorphic_add(ciphertext1, ciphertext2, public_key):
    n, g = public_key
    n_squared = n * n
    # E(m1 + m2) = E(m1) * E(m2) mod n^2
    return (ciphertext1 * ciphertext2) % n_squared
a = int(input("Enter first integer: "))
b = int(input("Enter second integer: "))
public_key, private_key = generate_keypair()
ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)
ciphertext_sum = homomorphic_add(
    ciphertext_a,
    ciphertext_b,
    public_key
)
decrypted_sum = decrypt(
    private_key,
    public_key,
    ciphertext_sum
)
print("\nPaillier Encryption")
print("First integer:", a)
print("Ciphertext of first integer:", ciphertext_a)
print("\nSecond integer:", b)
print("Ciphertext of second integer:", ciphertext_b)
print("\nCiphertext of encrypted addition:", ciphertext_sum)
print("\nDecrypted sum:", decrypted_sum)
print("Expected sum:", a + b)
if decrypted_sum == a + b:
    print("Verification: SUCCESS")
else:
    print("Verification: FAILED")
