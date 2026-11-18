from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certificates"
RESULTS = ROOT / "results"

RESULTS.mkdir(exist_ok=True)

# Alice reads Bob's public certificate.
bob_cert = x509.load_pem_x509_certificate(
    (CERTS / "bob_certificate.pem").read_bytes()
)
bob_public_key = bob_cert.public_key()

message = "Hello Bob! This is Alice sending an encrypted message."
plaintext = message.encode("utf-8")

# Encrypt with RSA-OAEP and SHA-256.
ciphertext = bob_public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

# Save only the encrypted bytes.
output_file = RESULTS / "alice_to_bob.bin"
output_file.write_bytes(ciphertext)

print("Alice encrypted the message successfully.")
print(f"Original message length: {len(plaintext)} bytes")
print(f"Encrypted data length: {len(ciphertext)} bytes")
print(f"Encrypted file: {output_file}")
print("Alice does not need Bob's private key to encrypt.")
