# Information Security Lab - Master Code Decision Guide

Use this guide to decide which program to open after reading an exam question.

## 1. Ten-second selection method

Underline five things in the question:

```text
1. What encrypts the actual data?
2. Is the symmetric key encrypted or exchanged?
3. What creates the digital signature?
4. What is hashed: plaintext or ciphertext?
5. Who is allowed to decrypt?
```

Then use this table:

| Wording in the question | Start with |
|---|---|
| AES/DES encrypts record; RSA/ElGamal signs; three roles | `master_secure_records.py` |
| AES encrypts file; RSA encrypts AES key; ElGamal encrypts authorization code | `master_hybrid_system.py` |
| RSA public key directly encrypts the record | `master_rsa_healthsecure.py` |
| DH derives AES/DES key; roles verify and decrypt | `master_dh_secure_records.py` |
| AES/DES encrypts; Schnorr signs; roles verify and decrypt | `master_schnorr_secure_records.py` |
| Only one algorithm is requested | Use the numbered basic program |
| Client and server are explicitly requested | Use the matching client/server pair |

## 2. The five integrated master systems

### Master 1 - `master_secure_records.py`

Use for the most common role-based flow:

```text
File -> AES/DES -> ciphertext -> SHA-256 -> RSA/ElGamal signature
Receiver -> verify hash and signature -> decrypt
Auditor -> verify only; never decrypt
```

Configuration to change:

```python
SYMMETRIC_ALGORITHM = "AES"       # or "DES"
SIGNATURE_ALGORITHM = "RSA"       # or "ELGAMAL"
ROLE_NAMES = ("Creator", "Receiver", "Auditor")
```

AES key sizes:

```text
AES-128 = 16 bytes
AES-192 = 24 bytes
AES-256 = 32 bytes
DES     = 8 bytes
```

### Master 2 - `master_hybrid_system.py`

Use when the question explicitly says that RSA encrypts the AES key:

```text
File -> AES encryption
AES key -> RSA encryption
Authorization code -> ElGamal encryption
AES ciphertext -> SHA-256
```

Key phrase: **"Encrypt the AES key using RSA."**

### Master 3 - `master_rsa_healthsecure.py`

Use only when RSA directly encrypts the actual record:

```text
Record -> RSA-OAEP chunks -> ciphertext
Ciphertext -> SHA-256 and RSA signature
Authorized role -> verify -> RSA decrypt
```

Key phrase: **"Encrypt the patient/record information using the RSA public key."**

### DH role master - `master_dh_secure_records.py`

Use when Diffie-Hellman establishes the AES/DES key in a role-based system:

```text
Creator DH private + receiver DH public -> shared secret
Receiver DH private + creator DH public -> same secret
SHA-256(shared secret) -> AES/DES key
AES/DES -> encrypt record
RSA -> sign ciphertext
```

Diffie-Hellman is key exchange, not a signature.

### Schnorr role master - `master_schnorr_secure_records.py`

Use when the question specifically requests a Schnorr signature:

```text
AES/DES -> encrypt record
SHA-256 -> integrity
Schnorr private key -> sign ciphertext
Schnorr public key -> verify
```

Schnorr signs; it does not encrypt the record.

## 3. RSA wording: the major exam trap

| RSA wording | RSA's job | File |
|---|---|---|
| "Sign using RSA private key" | Digital signature | `master_secure_records.py` |
| "Encrypt AES key using RSA public key" | Hybrid key wrapping | `master_hybrid_system.py` |
| "Encrypt record using RSA public key" | Direct record encryption | `master_rsa_healthsecure.py` |

## 4. Algorithm-purpose table

| Algorithm | What it normally does in these programs |
|---|---|
| AES/DES/3DES | Encrypts actual file or record |
| RSA | Can encrypt a small key, directly encrypt small/chunked data, or create signatures |
| ElGamal | Can encrypt data/key/authorization code or create a signature; read the verb in the question |
| Schnorr | Digital signature only |
| Diffie-Hellman | Establishes a shared secret; not encryption and not a signature |
| ECC/ECDH | Establishes a shared secret; AES normally encrypts the actual file |
| Rabin | Asymmetric encryption; decryption produces four possible roots |
| SHA-256 | Integrity hash or digest used by a signature |

## 5. Modes and padding

| Mode | IV/nonce | Padding normally used? |
|---|---|---|
| ECB | None | Yes unless explicitly unpadded |
| CBC | IV | Yes |
| CFB | IV | No |
| OFB | IV | No |
| CTR | Nonce | No |
| GCM | Nonce and authentication tag | No |

ECB unpadded requires plaintext length to be a multiple of the block size:

```text
AES block size = 16 bytes
DES block size = 8 bytes
```

Mode changes affect encryption/decryption only. Hashing, signatures, roles and timestamps remain
the same.

## 6. Basic and non-role programs in `IS_Lab_Master_Codes.zip`

| File | Use it for |
|---|---|
| `01_classical_ciphers.py` | Additive, multiplicative, affine, Vigenere, autokey, Playfair, Hill and transposition |
| `02_block_ciphers.py` | AES/DES/3DES and ECB/CBC/CFB/OFB/CTR encryption/decryption |
| `03_asymmetric_ciphers.py` | RSA, ElGamal, Rabin, ECC hybrid and DH |
| `04_hashing.py` | Custom 5381 hash, MD5, SHA-1, SHA-256, timing and tampering |
| `05_hash_socket_server.py` + `06_hash_socket_client.py` | Client/server integrity verification |
| `07_digital_signatures.py` | RSA, ElGamal and Schnorr signatures |
| `08_signature_socket_server.py` + `09_signature_socket_client.py` | RSA signature over sockets |
| `10_access_control_and_kdf.py` | KDF, RBAC, ABAC, DAC, MAC/Bell-LaPadula and time access |

## 7. Variation programs in `IS_Lab_Variations_Addon.zip`

### Key exchange

| File | Flow |
|---|---|
| `11_diffie_hellman_aes.py` | Classical DH -> AES-128-CBC |
| `12_ecdh_aes_gcm.py` | P-256 ECDH -> AES-256-GCM |
| `13_authenticated_dh_rsa.py` | RSA signatures authenticate DH public values |

### Direct asymmetric encryption

| File | Flow |
|---|---|
| `14_rsa_oaep_file.py` | RSA-OAEP chunked file encryption/decryption |
| `15_elgamal_encryption.py` | ElGamal bytewise encryption/decryption |
| `16_rabin_encryption.py` | Rabin integer encryption and four-root decryption |
| `17_ecc_hybrid_file.py` | Ephemeral P-256 ECDH -> AES-GCM file encryption |

### Other hybrid/non-role flows

| File | Flow |
|---|---|
| `18_aes_rsa_wrap_rsa_signature.py` | AES data + RSA-wrapped AES key + separate RSA signature |
| `19_aes_elgamal_key_wrap.py` | AES data + ElGamal-wrapped AES key |
| `20_sign_then_encrypt.py` | RSA-sign plaintext first, then AES-encrypt plaintext and signature |
| `21_secure_sender.py` + `22_secure_receiver.py` | AES-CBC + SHA-256 + RSA signature socket transfer |
| `23_performance_comparison.py` | Compare AES, DES and RSA timing |
| `24_weak_rsa_attack.py` | Factor deliberately weak RSA and recover private key |

## 8. Public-key client/server examples

Use `Public_Key_Client_Server_Examples.zip`.

| Server and client | Correct cryptographic flow |
|---|---|
| `ecc_server.py` + `ecc_client.py` | P-256 ECDH derives AES-GCM key; AES encrypts message |
| `elgamal_server.py` + `elgamal_client.py` | Server ElGamal public key encrypts client message |
| `simple_schnorr_server.py` + `simple_schnorr_client.py` | Client Schnorr-signs; server verifies |
| `dh_server.py` + `dh_client.py` | Classical DH derives AES-CBC key; AES encrypts message |

Always run the server first and client second in another terminal.

## 9. Hash/sign target: read the wording exactly

Most samples use encrypt-then-sign:

```text
plaintext -> encrypt -> ciphertext -> hash/sign ciphertext
```

If the question says "sign the original record before encryption," use sign-then-encrypt:

```text
plaintext -> hash/sign plaintext -> encrypt plaintext and signature
```

The sender and receiver must hash/verify the same representation.

## 10. Standard verification condition

For signed systems:

```python
if integrity_valid and signature_valid:
    decrypt()
else:
    print("Verification failed")
    print("Decryption denied")
```

For a hashing-only system:

```python
if integrity_valid:
    decrypt()
else:
    print("Integrity failed")
```

## 11. Tampering demonstration

```python
tampered = bytearray(ciphertext)
tampered[0] ^= 1
ciphertext = bytes(tampered)
```

Expected result when the original hash/signature is retained:

```text
Integrity: FAILED
Signature: INVALID
Decryption denied
```

## 12. Quick exam priority

Study in this order:

1. `master_secure_records.py`
2. Mode/padding changes: ECB, CBC and unpadded input rules
3. `master_hybrid_system.py`
4. `master_rsa_healthsecure.py`
5. `master_dh_secure_records.py`
6. `master_schnorr_secure_records.py`
7. Standalone/client-server variations only after the above are clear

The domain name (hospital, college, bank, law firm) does not choose the master. The algorithm
that encrypts the actual data and the stated purpose of RSA/ElGamal choose the master.
