
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "keys"

NODES = ["alice", "bob", "carol", "dave"]


def generate_keys():

    for node in NODES:

        node_dir = KEYS_DIR / node
        node_dir.mkdir(parents=True, exist_ok=True)

        private_key = ec.generate_private_key(
            ec.SECP256K1()
        )

        public_key = private_key.public_key()

        private_path = node_dir / f"{node}_ecdsa_private.pem"
        public_path = node_dir / f"{node}_ecdsa_public.pem"

        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        public_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

        print(f"[OK] ECDSA keys generated for {node.upper()}")


if __name__ == "__main__":
    generate_keys()
