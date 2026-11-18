import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certificates"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

# Load Bob's public key from his certificate.
bob_cert = x509.load_pem_x509_certificate(
    (CERTS / "bob_certificate.pem").read_bytes()
)
bob_public_key = bob_cert.public_key()

# Generate a fresh random 256-bit AES key and 96-bit nonce.
aes_key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)

message = (
    "Hello Bob! This is a confidential message encrypted "
    "with AES-256-GCM. It can also protect large files."
).encode("utf-8")

# Encrypt the message and authenticate its contents.
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(nonce, message, None)

# Protect the AES key with Bob's RSA public key.
encrypted_aes_key = bob_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

# Store the encrypted key, nonce and ciphertext.
package = {
    "algorithm": "AES-256-GCM",
    "key_encryption": "RSA-OAEP-SHA256",
    "nonce": base64.b64encode(nonce).decode("ascii"),
    "encrypted_aes_key": base64.b64encode(
        encrypted_aes_key
    ).decode("ascii"),
    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
}

output_file = RESULTS / "hybrid_message.json"
output_file.write_text(
    json.dumps(package, indent=2),
    encoding="utf-8",
)

print("Alice encrypted the message successfully.")
print(f"Original message size: {len(message)} bytes")
print(f"Encrypted package: {output_file}")
print("The AES key is protected with Bob's RSA public key.")
