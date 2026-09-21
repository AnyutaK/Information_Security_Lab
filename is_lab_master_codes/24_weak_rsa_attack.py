"""Factor a deliberately weak RSA modulus and recover its private key."""

from math import isqrt


def factor_modulus(n):
    for candidate in range(2, isqrt(n) + 1):
        if n % candidate == 0:
            return candidate, n // candidate
    raise ValueError("No factors found")


def main():
    # Vulnerable toy RSA parameters.
    p, q, e = 61, 53, 17
    n = p * q
    phi = (p - 1) * (q - 1)
    legitimate_d = pow(e, -1, phi)

    plaintext = input("Message: ").encode()
    ciphertext = [pow(byte, e, n) for byte in plaintext]
    print("Public key (n, e):", (n, e))
    print("Ciphertext:", ciphertext)

    # Attacker knows only n and e and factors the weak modulus.
    recovered_p, recovered_q = factor_modulus(n)
    recovered_phi = (recovered_p - 1) * (recovered_q - 1)
    recovered_d = pow(e, -1, recovered_phi)
    recovered = bytes(pow(value, recovered_d, n) for value in ciphertext)

    print("Recovered factors:", recovered_p, recovered_q)
    print("Recovered private exponent:", recovered_d)
    print("Matches legitimate private exponent:", recovered_d == legitimate_d)
    print("Recovered plaintext:", recovered.decode())
    print("Mitigation: use randomly generated large primes and RSA-2048 or stronger.")


if __name__ == "__main__":
    main()
