"""Lab 2: DES, Triple-DES and AES encryption/decryption in common modes."""

import base64
import time
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def normalize_key(algorithm, key_text):
    sizes = {"DES": 8, "3DES": 24, "AES-128": 16, "AES-192": 24, "AES-256": 32}
    size = sizes[algorithm]
    # Interpret an exact 2*size hexadecimal string as bytes; otherwise use text.
    if len(key_text) == 2 * size and all(ch in "0123456789abcdefABCDEF" for ch in key_text):
        key = bytes.fromhex(key_text)
    else:
        raw = key_text.encode()
        key = (raw + b"0" * size)[:size]
    return DES3.adjust_key_parity(key) if algorithm == "3DES" else key


def cipher_module(algorithm):
    return DES if algorithm == "DES" else DES3 if algorithm == "3DES" else AES


def encrypt(plaintext, key, algorithm="AES-128", mode="CBC"):
    module = cipher_module(algorithm)
    data, block = plaintext.encode(), module.block_size
    mode = mode.upper()
    if mode == "ECB":
        cipher = module.new(key, module.MODE_ECB)
        return {"ciphertext": cipher.encrypt(pad(data, block)), "iv": None, "nonce": None}
    if mode == "CBC":
        cipher = module.new(key, module.MODE_CBC)
        return {"ciphertext": cipher.encrypt(pad(data, block)), "iv": cipher.iv, "nonce": None}
    if mode == "CFB":
        cipher = module.new(key, module.MODE_CFB, segment_size=8)
        return {"ciphertext": cipher.encrypt(data), "iv": cipher.iv, "nonce": None}
    if mode == "OFB":
        cipher = module.new(key, module.MODE_OFB)
        return {"ciphertext": cipher.encrypt(data), "iv": cipher.iv, "nonce": None}
    if mode == "CTR":
        cipher = module.new(key, module.MODE_CTR)
        return {"ciphertext": cipher.encrypt(data), "iv": None, "nonce": cipher.nonce}
    raise ValueError("Use ECB, CBC, CFB, OFB or CTR")


def decrypt(package, key, algorithm="AES-128", mode="CBC"):
    module, mode = cipher_module(algorithm), mode.upper()
    if mode == "ECB":
        cipher = module.new(key, module.MODE_ECB)
    elif mode == "CBC":
        cipher = module.new(key, module.MODE_CBC, iv=package["iv"])
    elif mode == "CFB":
        cipher = module.new(key, module.MODE_CFB, iv=package["iv"], segment_size=8)
    elif mode == "OFB":
        cipher = module.new(key, module.MODE_OFB, iv=package["iv"])
    elif mode == "CTR":
        cipher = module.new(key, module.MODE_CTR, nonce=package["nonce"])
    else:
        raise ValueError("Invalid mode")
    result = cipher.decrypt(package["ciphertext"])
    if mode in ("ECB", "CBC"):
        result = unpad(result, module.block_size)
    return result.decode()


def performance_demo(message):
    print("\nAlgorithm/mode timing (milliseconds)")
    for algorithm in ("DES", "AES-128", "AES-192", "AES-256"):
        for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
            key = get_random_bytes({"DES": 8, "AES-128": 16, "AES-192": 24, "AES-256": 32}[algorithm])
            start = time.perf_counter()
            package = encrypt(message, key, algorithm, mode)
            middle = time.perf_counter()
            decrypt(package, key, algorithm, mode)
            end = time.perf_counter()
            print(f"{algorithm:7} {mode:3}: enc={(middle-start)*1000:.4f}, dec={(end-middle)*1000:.4f}")


def main():
    print("Algorithms: DES, 3DES, AES-128, AES-192, AES-256")
    algorithm = input("Algorithm: ").upper()
    mode = input("Mode (ECB/CBC/CFB/OFB/CTR): ").upper()
    key = normalize_key(algorithm, input("Key text or exact-length hexadecimal key: "))
    plaintext = input("Plaintext: ")
    package = encrypt(plaintext, key, algorithm, mode)
    print("Key (hex):", key.hex())
    if package["iv"]:
        print("IV (hex):", package["iv"].hex())
    if package["nonce"]:
        print("Nonce (hex):", package["nonce"].hex())
    print("Ciphertext (Base64):", base64.b64encode(package["ciphertext"]).decode())
    print("Decrypted:", decrypt(package, key, algorithm, mode))
    if input("Run timing comparison? (y/n): ").lower() == "y":
        performance_demo(plaintext)


if __name__ == "__main__":
    main()
