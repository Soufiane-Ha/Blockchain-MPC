
import csv
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import algorithms

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

os.makedirs(RESULTS_DIR, exist_ok=True)

# Alice's RSA private key is used here to obtain the matching public key.
with open(os.path.join(KEYS_DIR, "alice_private_key.pem"), "rb") as f:
    alice_private_key = serialization.load_pem_private_key(
        f.read(), password=None
    )

alice_public_key = alice_private_key.public_key()

# Reuse a single AES key for this local performance experiment.
aes_key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(aes_key)

sizes = [
    ("1KB", 1024),
    ("1MB", 1024 * 1024),
    ("10MB", 10 * 1024 * 1024),
]

rows = []

for label, size in sizes:
    data = os.urandom(size)

    # AES-256-GCM: encrypt and decrypt the complete message.
    nonce = os.urandom(12)

    start = time.perf_counter()
    ciphertext = aes.encrypt(nonce, data, None)
    aes_encrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    plaintext = aes.decrypt(nonce, ciphertext, None)
    aes_decrypt_time = time.perf_counter() - start

    assert plaintext == data

    # RSA-OAEP cannot encrypt these large messages directly.
    # Instead, measure RSA encryption/decryption of the AES key.
    start = time.perf_counter()
    wrapped_key = alice_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    rsa_encrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    recovered_key = alice_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    rsa_decrypt_time = time.perf_counter() - start

    assert recovered_key == aes_key

    rows.append({
        "data_size": label,
        "data_bytes": size,
        "aes_encrypt_ms": round(aes_encrypt_time * 1000, 3),
        "aes_decrypt_ms": round(aes_decrypt_time * 1000, 3),
        "rsa_key_encrypt_ms": round(rsa_encrypt_time * 1000, 3),
        "rsa_key_decrypt_ms": round(rsa_decrypt_time * 1000, 3),
        "aes_ciphertext_bytes": len(ciphertext),
        "rsa_wrapped_key_bytes": len(wrapped_key),
    })

output_path = os.path.join(RESULTS_DIR, "benchmark.csv")

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print("\nBenchmark completed successfully.\n")

for row in rows:
    print(
        f"{row['data_size']}: "
        f"AES encrypt={row['aes_encrypt_ms']} ms, "
        f"AES decrypt={row['aes_decrypt_ms']} ms, "
        f"RSA key encrypt={row['rsa_key_encrypt_ms']} ms, "
        f"RSA key decrypt={row['rsa_key_decrypt_ms']} ms"
    )

print(f"\nCSV saved to: {output_path}")
