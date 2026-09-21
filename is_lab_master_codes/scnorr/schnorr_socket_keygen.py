"""Generate the client's Schnorr key pair before starting client/server."""

import json
import os
import secrets
from pathlib import Path

P = 23
Q = 11
G = 2

PRIVATE_FILE = Path("schnorr_client_private.json")
PUBLIC_FILE = Path("schnorr_client_public.json")


def main():
    private_key = secrets.randbelow(Q - 1) + 1
    public_value = pow(G, private_key, P)

    PRIVATE_FILE.write_text(json.dumps({"x": private_key}, indent=2))
    PUBLIC_FILE.write_text(
        json.dumps({"p": P, "q": Q, "g": G, "y": public_value}, indent=2)
    )
    os.chmod(PRIVATE_FILE, 0o600)

    print("Schnorr keys generated")
    print("Private key file:", PRIVATE_FILE)
    print("Public key file:", PUBLIC_FILE)
    print("Public key:", (P, Q, G, public_value))


if __name__ == "__main__":
    main()

