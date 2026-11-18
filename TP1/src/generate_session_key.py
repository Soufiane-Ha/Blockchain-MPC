import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = ROOT / "keys" / "session_key.bin"

if KEY_FILE.exists():
    raise SystemExit(
        "Key already exists. Keeping it unchanged."
    )

KEY_FILE.write_bytes(secrets.token_bytes(32))
print("Created a 32-byte test session key.")
