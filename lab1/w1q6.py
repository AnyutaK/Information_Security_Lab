import math
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MOD = 26
def mod_inverse(a, m):
    """Find the modular inverse of a modulo m."""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None
def find_affine_key(plain, cipher):
    p1 = ALPHABET.index(plain[0].upper())
    p2 = ALPHABET.index(plain[1].upper())
    c1 = ALPHABET.index(cipher[0].upper())
    c2 = ALPHABET.index(cipher[1].upper())
    denominator = (p2 - p1) % MOD
    numerator = (c2 - c1) % MOD
    inverse = mod_inverse(denominator, MOD)
    if inverse is None:
        return None
    a = (numerator * inverse) % MOD
    b = (c1 - a * p1) % MOD
    if math.gcd(a, MOD) != 1:
        return None
    return a, b
def decrypt(ciphertext, a, b):
    """Decrypt an affine cipher."""
    a_inverse = mod_inverse(a, MOD)
    if a_inverse is None:
        return None
    plaintext = ""
    for char in ciphertext.upper():
        if char in ALPHABET:
            c = ALPHABET.index(char)
            p = (a_inverse * (c - b)) % MOD
            plaintext += ALPHABET[p]
        else:
            plaintext += char
    return plaintext
ciphertext = input("Enter the ciphertext: ")
known_plaintext = input(
    "Enter the known plaintext (e.g. AB): "
)
known_ciphertext = input(
    "Enter the corresponding ciphertext (e.g. GL): "
)
if len(known_plaintext) != 2 or len(known_ciphertext) != 2:
    print("Error: Enter exactly two letters for each.")
    exit()
key = find_affine_key(
    known_plaintext,
    known_ciphertext
)
if key is None:
    print("Could not determine a valid affine key.")
    exit()
a, b = key
print("\nAffine key found:")
print("a =", a)
print("b =", b)
plaintext = decrypt(ciphertext, a, b)
print("\nDecrypted message:")
print(plaintext)