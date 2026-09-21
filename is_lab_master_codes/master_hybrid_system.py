"""
AES-128-CBC file encryption + RSA-OAEP key wrapping + ElGamal authorization code.
Also performs SHA-256 integrity verification and an explicit tampering demonstration.
"""

import base64
import hashlib
import json
import secrets
from pathlib import Path
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BASE = Path(__file__).resolve().parent / "hybrid_output"
P, G = 7919, 2


def elgamal_generate():
    private = secrets.randbelow(P - 3) + 2
    return (P, G, pow(G, private, P)), private


def elgamal_encrypt_bytes(data, public):
    p, g, y = public
    output = []
    for byte in data:
        k = secrets.randbelow(p - 3) + 2
        output.append([pow(g, k, p), byte * pow(y, k, p) % p])
    return output


def elgamal_decrypt_bytes(ciphertext, private, p):
    return bytes(c2 * pow(pow(c1, private, p), -1, p) % p for c1, c2 in ciphertext)


def sender_create_package():
    source = Path(input("Input .txt file: ").strip())
    if source.suffix.lower() != ".txt" or not source.is_file():
        raise ValueError("Valid .txt file required")
    authorization = input("Authorization code: ").encode()
    plaintext = source.read_bytes()

    aes_key, iv = get_random_bytes(16), get_random_bytes(16)
    aes_ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))
    digest = hashlib.sha256(aes_ciphertext).hexdigest()

    rsa_private = RSA.generate(2048)
    rsa_public = rsa_private.publickey()
    encrypted_aes_key = PKCS1_OAEP.new(rsa_public).encrypt(aes_key)

    elgamal_public, elgamal_private = elgamal_generate()
    encrypted_authorization = elgamal_encrypt_bytes(authorization, elgamal_public)

    BASE.mkdir(exist_ok=True)
    (BASE / "encrypted_message.bin").write_bytes(aes_ciphertext)
    (BASE / "encrypted_aes_key.bin").write_bytes(encrypted_aes_key)
    (BASE / "rsa_private.pem").write_bytes(rsa_private.export_key())
    (BASE / "rsa_public.pem").write_bytes(rsa_public.export_key())
    (BASE / "elgamal_authorization.json").write_text(json.dumps(encrypted_authorization))
    metadata = {
        "source_filename": source.name,
        "iv": base64.b64encode(iv).decode(),
        "sha256": digest,
        "elgamal_public": [str(v) for v in elgamal_public],
        "elgamal_private": str(elgamal_private),
        "expected_authorization": authorization.decode(),
    }
    (BASE / "metadata.json").write_text(json.dumps(metadata, indent=2))

    print("\nEncrypted message (Base64):", base64.b64encode(aes_ciphertext).decode())
    print("SHA-256:", digest)
    print("AES IV:", iv.hex())
    print("RSA public key:\n", rsa_public.export_key().decode())
    print("RSA values: n=", rsa_public.n, "e=", rsa_public.e)
    print("RSA-encrypted AES key (Base64):", base64.b64encode(encrypted_aes_key).decode())
    print("ElGamal public key (p,g,y):", elgamal_public)
    print("ElGamal-encrypted authorization:", encrypted_authorization)


def receiver_verify_and_decrypt(ciphertext_path=None):
    metadata = json.loads((BASE / "metadata.json").read_text())
    path = ciphertext_path or BASE / "encrypted_message.bin"
    ciphertext = Path(path).read_bytes()
    received_hash = hashlib.sha256(ciphertext).hexdigest()
    print("Stored sender hash:  ", metadata["sha256"])
    print("Receiver hash:       ", received_hash)
    if received_hash != metadata["sha256"]:
        print("INTEGRITY FAILED - decryption will not be performed.")
        return False

    encrypted_auth = json.loads((BASE / "elgamal_authorization.json").read_text())
    auth = elgamal_decrypt_bytes(encrypted_auth, int(metadata["elgamal_private"]),
                                 int(metadata["elgamal_public"][0])).decode()
    if auth != metadata["expected_authorization"]:
        print("AUTHORIZATION FAILED - decryption will not be performed.")
        return False

    rsa_private = RSA.import_key((BASE / "rsa_private.pem").read_bytes())
    aes_key = PKCS1_OAEP.new(rsa_private).decrypt((BASE / "encrypted_aes_key.bin").read_bytes())
    iv = base64.b64decode(metadata["iv"])
    plaintext = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
    print("Integrity: VALID")
    print("Authorization: VALID")
    print("Decrypted AES key:", aes_key.hex())
    print("Decrypted authorization code:", auth)
    print("Original file content:\n" + plaintext.decode())
    return True


def tamper_demo():
    original = (BASE / "encrypted_message.bin").read_bytes()
    tampered = bytearray(original)
    tampered[0] ^= 1
    path = BASE / "tampered_message.bin"
    path.write_bytes(tampered)
    print("Modified one byte and stored tampered_message.bin")
    receiver_verify_and_decrypt(path)


def main():
    while True:
        print("\n1 Create/encrypt package  2 Verify/decrypt  3 Tampering test  0 Exit")
        choice = input("Choice: ")
        try:
            if choice == "1": sender_create_package()
            elif choice == "2": receiver_verify_and_decrypt()
            elif choice == "3": tamper_demo()
            elif choice == "0": break
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
            print("Error:", error)


if __name__ == "__main__":
    main()
