import os
import socket
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
KEY = (ROOT / "keys" / "session_key.bin").read_bytes()

HOST = "127.0.0.1"
PORT = 5001
AAD = b"TP1|Alice|Bob"

message = "Hello Bob! This message is encrypted over TCP.".encode("utf-8")

# Generate a fresh 96-bit nonce for this encryption.
nonce = os.urandom(12)
ciphertext = AESGCM(KEY).encrypt(nonce, message, AAD)

# Packet = nonce + ciphertext and authentication tag.
packet = nonce + ciphertext
header = struct.pack("!I", len(packet))

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    sock.sendall(header + packet)

print("Alice sent the encrypted message.")
print("Plaintext length:", len(message), "bytes")
print("Encrypted packet length:", len(packet), "bytes")
