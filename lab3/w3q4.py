import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_rsa_keys():
    start = time.perf_counter()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    end = time.perf_counter()
    return private_key, public_key, end - start
def rsa_encrypt_file(data, public_key):
    aes_key = AESGCM.generate_key(bit_length=256)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )
    return encrypted_key, nonce, encrypted_data
def rsa_decrypt_file(encrypted_key, nonce, encrypted_data, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )
    return decrypted_data
def generate_ecc_keys():
    start = time.perf_counter()
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    public_key = private_key.public_key()
    end = time.perf_counter()
    return private_key, public_key, end - start
def derive_ecc_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Secure File Transfer"
    ).derive(shared_secret)
    return aes_key
def ecc_encrypt_file(data, public_key):
    ephemeral_private_key = ec.generate_private_key(
        ec.SECP256R1()
    )
    ephemeral_public_key = ephemeral_private_key.public_key()
    aes_key = derive_ecc_key(
        ephemeral_private_key,
        public_key
    )
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )
    return ephemeral_public_key, nonce, encrypted_data
def ecc_decrypt_file(
    ephemeral_public_key,
    nonce,
    encrypted_data,
    private_key
):
    aes_key = derive_ecc_key(
        private_key,
        ephemeral_public_key
    )
    aesgcm = AESGCM(aes_key)
    decrypted_data = aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )
    return decrypted_data
def test_file_size(size_mb):
    print(f"Testing {size_mb} MB file")
    data = os.urandom(size_mb * 1024 * 1024)
    rsa_private, rsa_public, rsa_key_time = generate_rsa_keys()
    print("\nRSA-2048")
    print("Key generation time:", rsa_key_time, "seconds")
    start = time.perf_counter()
    rsa_encrypted_key, rsa_nonce, rsa_ciphertext = rsa_encrypt_file(
        data,
        rsa_public
    )
    rsa_encrypt_time = time.perf_counter() - start
    print("Encryption time:", rsa_encrypt_time, "seconds")
    start = time.perf_counter()
    rsa_decrypted = rsa_decrypt_file(
        rsa_encrypted_key,
        rsa_nonce,
        rsa_ciphertext,
        rsa_private
    )
    rsa_decrypt_time = time.perf_counter() - start
    print("Decryption time:", rsa_decrypt_time, "seconds")
    print("RSA verification:", rsa_decrypted == data)
    ecc_private, ecc_public, ecc_key_time = generate_ecc_keys()
    print("\nECC - secp256r1")
    print("Key generation time:", ecc_key_time, "seconds")
    start = time.perf_counter()
    ephemeral_public, ecc_nonce, ecc_ciphertext = ecc_encrypt_file(
        data,
        ecc_public
    )
    ecc_encrypt_time = time.perf_counter() - start
    print("Encryption time:", ecc_encrypt_time, "seconds")
    start = time.perf_counter()
    ecc_decrypted = ecc_decrypt_file(
        ephemeral_public,
        ecc_nonce,
        ecc_ciphertext,
        ecc_private
    )
    ecc_decrypt_time = time.perf_counter() - start
    print("Decryption time:", ecc_decrypt_time, "seconds")
    print("ECC verification:", ecc_decrypted == data)
def main():
    print("SECURE FILE TRANSFER")
    print("RSA-2048 vs ECC-secp256r1")
    test_file_size(1)
    test_file_size(10)
if __name__ == "__main__":
    main()