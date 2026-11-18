import socket
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
KEY = (ROOT / "keys" / "session_key.bin").read_bytes()

HOST = "127.0.0.1"
PORT = 5001
AAD = b"TP1|Alice|Bob"


def recv_exact(conn, size):
    data = bytearray()

    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        data.extend(chunk)

    return bytes(data)


print(f"Bob listening on {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    conn, address = server.accept()

    with conn:
        print("Connection from:", address)

        # Read the 4-byte message length.
        length = struct.unpack("!I", recv_exact(conn, 4))[0]

        if length < 12 + 16 or length > 1_000_000:
            raise ValueError("Invalid encrypted message length.")

        packet = recv_exact(conn, length)
        nonce = packet[:12]
        ciphertext = packet[12:]

        try:
            plaintext = AESGCM(KEY).decrypt(
                nonce, ciphertext, AAD
            )
        except InvalidTag:
            print("ERROR: Authentication failed; message rejected.")
            raise SystemExit(1)

        print("Message authenticated and decrypted:")
        print(plaintext.decode("utf-8"))
