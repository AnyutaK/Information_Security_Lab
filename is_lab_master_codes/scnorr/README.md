# Schnorr Secure Client-Server

## Simple signature-only version

This pair directly mirrors the common RSA socket example, but uses Schnorr mathematics:

```bash
python simple_schnorr_server.py
python simple_schnorr_client.py
```

The client generates a Schnorr key pair, signs a message and sends the message, signature and
public key. The server verifies the signature. No RSA classes or `pkcs1_15` calls are used.

## Encrypted-file version

Flow:

```text
Client file -> AES/DES-CBC -> SHA-256 -> Schnorr signature -> socket
Server -> verify hash -> verify Schnorr -> decrypt only if both are valid
```

## Setup

```bash
python -m pip install pycryptodome
python schnorr_socket_keygen.py
```

Open two terminals. Start the server first:

```bash
python schnorr_secure_server.py
```

Then run the client:

```bash
python schnorr_secure_client.py
```

Enter the same symmetric key in both terminals.

- AES-128: `1234567890123456`
- AES-192: `123456789012345678901234`
- AES-256: `12345678901234567890123456789012`
- DES: `12345678`

To change the cipher, edit the configuration at the top of both client and server. Their
`SYMMETRIC_ALGORITHM` and `AES_KEY_SIZE` values must match.
