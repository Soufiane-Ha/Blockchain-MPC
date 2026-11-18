import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent

bob_private_key = serialization.load_pem_private_key(
    (ROOT / "keys" / "bob_private_key.pem").read_bytes(),
    password=None,
)

package = json.loads(
    (ROOT / "results" / "hybrid_message.json").read_text(
        encoding="utf-8"
    )
)

nonce = base64.b64decode(package["nonce"])
encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
ciphertext = bytearray(base64.b64decode(package["ciphertext"]))

# Modify one bit in the encrypted message.
ciphertext[0] ^= 1

aes_key = bob_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

try:
    AESGCM(aes_key).decrypt(nonce, bytes(ciphertext), None)
except InvalidTag:
    print("PASS: AES-GCM detected tampering and rejected the message.")
else:
    raise SystemExit("FAIL: Modified message was unexpectedly accepted.")
