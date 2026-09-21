"""Compare AES, DES and RSA encryption/decryption time."""

import time
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def average_ms(function, repetitions=1000):
    start = time.perf_counter()
    for _ in range(repetitions):
        function()
    return (time.perf_counter() - start) * 1000 / repetitions


def symmetric_test(module, key, message, repetitions=1000):
    iv = get_random_bytes(module.block_size)
    padded = pad(message, module.block_size)

    def encrypt_once():
        return module.new(key, module.MODE_CBC, iv).encrypt(padded)

    ciphertext = encrypt_once()

    def decrypt_once():
        return unpad(module.new(key, module.MODE_CBC, iv).decrypt(ciphertext), module.block_size)

    return average_ms(encrypt_once, repetitions), average_ms(decrypt_once, repetitions)


def main():
    message = input("Short message: ").encode()
    aes_enc, aes_dec = symmetric_test(AES, get_random_bytes(32), message)
    des_enc, des_dec = symmetric_test(DES, get_random_bytes(8), message)

    rsa_private = RSA.generate(2048)
    rsa_public = rsa_private.publickey()
    rsa_message = message[:190]

    def rsa_encrypt():
        return PKCS1_OAEP.new(rsa_public, hashAlgo=SHA256).encrypt(rsa_message)

    rsa_ciphertext = rsa_encrypt()

    def rsa_decrypt():
        return PKCS1_OAEP.new(rsa_private, hashAlgo=SHA256).decrypt(rsa_ciphertext)

    rsa_enc = average_ms(rsa_encrypt, 100)
    rsa_dec = average_ms(rsa_decrypt, 100)

    print("\nAverage time in milliseconds")
    print(f"AES-256-CBC encryption: {aes_enc:.6f}")
    print(f"AES-256-CBC decryption: {aes_dec:.6f}")
    print(f"DES-CBC encryption:     {des_enc:.6f}")
    print(f"DES-CBC decryption:     {des_dec:.6f}")
    print(f"RSA-2048 encryption:    {rsa_enc:.6f}")
    print(f"RSA-2048 decryption:    {rsa_dec:.6f}")


if __name__ == "__main__":
    main()

