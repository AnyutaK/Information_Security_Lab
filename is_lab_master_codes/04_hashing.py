"""Lab 5: custom hash, standard hashes, timing, collisions and tamper detection."""

import hashlib
import random
import string
import time


def custom_hash_5381(text):
    value = 5381
    for ch in text:
        value = ((value * 33) + ord(ch)) & 0xFFFFFFFF
        value ^= value >> 16  # extra bit mixing requested by the manual
    return value & 0xFFFFFFFF


def standard_hashes(data):
    raw = data.encode() if isinstance(data, str) else data
    return {
        "MD5": hashlib.md5(raw).hexdigest(),
        "SHA-1": hashlib.sha1(raw).hexdigest(),
        "SHA-256": hashlib.sha256(raw).hexdigest(),
    }


def benchmark(count=100, length=64):
    dataset = ["".join(random.choices(string.ascii_letters + string.digits, k=length))
               for _ in range(count)]
    constructors = {"MD5": hashlib.md5, "SHA-1": hashlib.sha1, "SHA-256": hashlib.sha256}
    for name, constructor in constructors.items():
        start = time.perf_counter()
        values = [constructor(item.encode()).hexdigest() for item in dataset]
        duration = (time.perf_counter() - start) * 1000
        collisions = len(values) - len(set(values))
        print(f"{name:7}: {duration:.4f} ms, collisions={collisions}")


def tamper_demo(message):
    original = hashlib.sha256(message.encode()).hexdigest()
    tampered = message + "X"
    received = hashlib.sha256(tampered.encode()).hexdigest()
    print("Original hash:", original)
    print("Tampered hash:", received)
    print("Integrity:", "VALID" if original == received else "FAILED - tampering detected")


if __name__ == "__main__":
    message = input("Message: ")
    print("Custom 5381 hash:", hex(custom_hash_5381(message)))
    for algorithm, digest in standard_hashes(message).items():
        print(f"{algorithm}: {digest}")
    benchmark()
    tamper_demo(message)
