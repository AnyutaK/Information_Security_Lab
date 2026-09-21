"""AES-128-CBC file encryption with the AES key protected by ElGamal."""

import hashlib
import secrets
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
G = 2


def generate_elgamal_keys():
    private = secrets.randbelow(P - 3) + 2
    return (P, G, pow(G, private, P)), private


def wrap_key(key, public_key):
    p, g, y = public_key
    message = int.from_bytes(key, "big")
    k = secrets.randbelow(p - 3) + 2
    return pow(g, k, p), message * pow(y, k, p) % p


def unwrap_key(cipher_pair, private_key, p, size=16):
    c1, c2 = cipher_pair
    shared = pow(c1, private_key, p)
    number = c2 * pow(shared, -1, p) % p
    return number.to_bytes(size, "big")


def main():
    path = Path(input("Input .txt file: ").strip())
    if path.suffix.lower() != ".txt" or not path.is_file():
        print("Valid .txt file required")
        return

    public, private = generate_elgamal_keys()
    aes_key, iv = get_random_bytes(16), get_random_bytes(16)
    ciphertext = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(pad(path.read_bytes(), 16))
    stored_hash = hashlib.sha256(ciphertext).hexdigest()
    encrypted_key = wrap_key(aes_key, public)

    receiver_hash = hashlib.sha256(ciphertext).hexdigest()
    if receiver_hash != stored_hash:
        print("Integrity FAILED; decryption denied")
        return

    recovered_key = unwrap_key(encrypted_key, private, public[0])
    plaintext = unpad(AES.new(recovered_key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)

    print("ElGamal public key:", public)
    print("Ciphertext:", ciphertext.hex())
    print("Encrypted AES key (c1, c2):", encrypted_key)
    print("SHA-256:", stored_hash)
    print("Integrity: VALID")
    print("Recovered AES key:", recovered_key.hex())
    print("Recovered content:\n" + plaintext.decode())


if __name__ == "__main__":
    main()

