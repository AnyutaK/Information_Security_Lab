"""Educational ElGamal bytewise encryption and decryption."""

import secrets

P = 7919
G = 2


def generate_keys():
    private = secrets.randbelow(P - 3) + 2
    public = (P, G, pow(G, private, P))
    return public, private


def encrypt(data, public_key):
    p, g, y = public_key
    ciphertext = []
    for byte in data:
        k = secrets.randbelow(p - 3) + 2
        c1 = pow(g, k, p)
        c2 = byte * pow(y, k, p) % p
        ciphertext.append((c1, c2))
    return ciphertext


def decrypt(ciphertext, private_key, p):
    recovered = []
    for c1, c2 in ciphertext:
        shared = pow(c1, private_key, p)
        recovered.append(c2 * pow(shared, -1, p) % p)
    return bytes(recovered)


def main():
    public, private = generate_keys()
    plaintext = input("Message: ").encode()
    ciphertext = encrypt(plaintext, public)
    recovered = decrypt(ciphertext, private, public[0])

    print("Public key (p, g, y):", public)
    print("Private key x:", private)
    print("Ciphertext pairs:", ciphertext)
    print("Recovered plaintext:", recovered.decode())


if __name__ == "__main__":
    main()

