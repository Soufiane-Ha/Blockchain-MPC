import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Alice and Bob each generate a temporary ECDH key pair.
alice_private = ec.generate_private_key(ec.SECP256R1())
bob_private = ec.generate_private_key(ec.SECP256R1())

alice_public = alice_private.public_key()
bob_public = bob_private.public_key()

# Each party independently derives the shared secret.
alice_secret = alice_private.exchange(ec.ECDH(), bob_public)
bob_secret = bob_private.exchange(ec.ECDH(), alice_public)

if alice_secret != bob_secret:
    raise SystemExit("FAIL: ECDH secrets do not match.")

print("PASS: Alice and Bob derived the same ECDH secret.")

# Use the same context and salt so both derive the same AES key.
salt = os.urandom(16)
info = b"Blockchain-MPC-TP1-Alice-Bob"

def derive_aes_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)

alice_aes_key = derive_aes_key(alice_secret)
bob_aes_key = derive_aes_key(bob_secret)

if alice_aes_key != bob_aes_key:
    raise SystemExit("FAIL: Derived AES keys do not match.")

print("PASS: HKDF derived the same 256-bit AES key.")

# Alice encrypts a message; Bob decrypts it.
nonce = os.urandom(12)
message = b"Hello Bob! Our session key was derived with ECDH and HKDF."

ciphertext = AESGCM(alice_aes_key).encrypt(
    nonce,
    message,
    info,
)

plaintext = AESGCM(bob_aes_key).decrypt(
    nonce,
    ciphertext,
    info,
)

if plaintext != message:
    raise SystemExit("FAIL: Decrypted message differs from original.")

print("PASS: Bob decrypted and authenticated Alice's message.")
print("Received message:", plaintext.decode("utf-8"))
print("AES key length:", len(alice_aes_key), "bytes")
print("Shared secret length:", len(alice_secret), "bytes")
