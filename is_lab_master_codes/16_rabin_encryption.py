"""Educational Rabin integer encryption; decryption returns four possible roots."""

from Crypto.Util.number import getPrime, inverse


def blum_prime(bits=128):
    while True:
        value = getPrime(bits)
        if value % 4 == 3:
            return value


def generate_keys():
    p, q = blum_prime(), blum_prime()
    return p * q, (p, q)


def encrypt(message_number, public_n):
    if not 0 <= message_number < public_n:
        raise ValueError("Message integer must be smaller than n")
    return pow(message_number, 2, public_n)


def decrypt_roots(ciphertext, private_key):
    p, q = private_key
    n = p * q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    p_inverse_mod_q = inverse(p, q)
    q_inverse_mod_p = inverse(q, p)
    root1 = (p_inverse_mod_q * p * mq + q_inverse_mod_p * q * mp) % n
    root2 = n - root1
    root3 = (p_inverse_mod_q * p * mq - q_inverse_mod_p * q * mp) % n
    root4 = n - root3
    return root1, root2, root3, root4


def main():
    public, private = generate_keys()
    message = int(input("Enter a small positive integer: "))
    ciphertext = encrypt(message, public)
    roots = decrypt_roots(ciphertext, private)
    print("Public key n:", public)
    print("Private key (p, q):", private)
    print("Ciphertext:", ciphertext)
    print("Four possible plaintext roots:", roots)
    print("Original message found:", message in roots)


if __name__ == "__main__":
    main()

