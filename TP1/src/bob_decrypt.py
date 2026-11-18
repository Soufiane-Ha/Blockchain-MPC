from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
RESULTS = ROOT / "results"

private_key = serialization.load_pem_private_key(
    (KEYS / "bob_private_key.pem").read_bytes(),
    password=None,
)

ciphertext = (RESULTS / "alice_to_bob.bin").read_bytes()

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

print("Bob decrypted the message successfully.")
print("Message received:", plaintext.decode("utf-8"))
