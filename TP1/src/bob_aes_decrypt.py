import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
RESULTS = ROOT / "results"

# Load Bob's private key.
bob_private_key = serialization.load_pem_private_key(
    (KEYS / "bob_private_key.pem").read_bytes(),
    password=None,
)

package = json.loads(
    (RESULTS / "hybrid_message.json").read_text(encoding="utf-8")
)

nonce = base64.b64decode(package["nonce"])
encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
ciphertext = base64.b64decode(package["ciphertext"])

# Recover the AES key using Bob's RSA private key.
aes_key = bob_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

# Authenticate and decrypt the message.
plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

print("Bob decrypted and authenticated the message successfully.")
print("Message received:", plaintext.decode("utf-8"))
