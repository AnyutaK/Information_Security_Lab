# Information Security Lab - Master Code Pack

This pack follows IS Lab Manuals 1-6 and contains encryption **and** decryption, hashing,
signing/verification, socket demonstrations, tamper detection, and reusable role-based templates.

## Setup

```bash
python -m pip install -r requirements.txt
```

## Files

| File | Covers |
|---|---|
| `01_classical_ciphers.py` | Additive/Caesar, multiplicative, affine, Vigenere, autokey, Playfair, Hill, rail-fence and columnar transposition; encryption and decryption |
| `02_block_ciphers.py` | DES, 3DES, AES-128/192/256; ECB/CBC/CFB/OFB/CTR; timing |
| `03_asymmetric_ciphers.py` | Textbook RSA, practical RSA-OAEP, ElGamal, Rabin, ECC hybrid encryption and Diffie-Hellman |
| `04_hashing.py` | Manual's 5381 custom hash, MD5/SHA-1/SHA-256, collisions, timing and tamper check |
| `05_hash_socket_server.py` / `06_hash_socket_client.py` | SHA-256 client-server integrity verification, including multipart messages |
| `07_digital_signatures.py` | RSA, ElGamal and Schnorr sign/verify plus tampering test |
| `08_signature_socket_server.py` / `09_signature_socket_client.py` | Client-server RSA-signature verification |
| `10_access_control_and_kdf.py` | PBKDF2 key derivation plus RBAC, ABAC, DAC, Bell-LaPadula/MAC and time-based checks |
| `master_secure_records.py` | Main exam template: AES/DES + RSA/ElGamal signature + SHA-256 + RBAC + timestamps + tampering |
| `master_hybrid_system.py` | AES file encryption + RSA-wrapped AES key + ElGamal authorization code + hashing + tamper test |
| `master_rsa_healthsecure.py` | RSA-only Doctor/Nurse/Admin HealthSecure template |

## Fast exam selection

- **AES/DES + SHA-256 + RSA/ElGamal signature + three roles:** use `master_secure_records.py`.
- **AES + RSA-encrypted AES key + ElGamal authorization:** use `master_hybrid_system.py`.
- **RSA encrypts the actual patient record:** use `master_rsa_healthsecure.py`.
- Change `ROLE_NAMES` near the top of `master_secure_records.py` to rename roles, e.g.
  `("Client", "Lawyer", "Compliance Officer")`.

## Important exam rules

1. Hash the **ciphertext** at upload and verification time.
2. Sign the same SHA-256 digest that will later be verified.
3. Check hash and signature **before** decryption.
4. Never expose the private/signing key to verifier or auditor roles.
5. DES is included only because the syllabus requires it; it is obsolete in real systems.
6. RSA should normally encrypt a random AES key, not a large file. The RSA-only template chunks
   data only to match the stated question.

Each program contains its own prompts and can be run independently with `python filename.py`.

## Manual corrections/ambiguities

- The Lab 3 ElGamal example lists `p=7919`, `g=2`, private `x=2999`, and public `h=6465`.
  These values are inconsistent because `2^2999 mod 7919 = 3868`, not 6465. The code computes
  the public value from the private key so encryption and decryption work.
- The AES-192 exercise prints a 32-hex-character key, which represents only 128 bits. AES-192
  requires 48 hexadecimal characters (24 bytes).
