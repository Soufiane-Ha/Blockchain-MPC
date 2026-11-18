from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent

carol_key = serialization.load_pem_private_key(
    (ROOT / "keys" / "carol_private_key.pem").read_bytes(),
    password=None,
)

ciphertext = (ROOT / "results" / "alice_to_bob.bin").read_bytes()

try:
    carol_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
except ValueError:
    print("PASS: Carol cannot decrypt Bob's message.")
else:
    raise SystemExit("FAIL: Unexpected successful decryption.")

