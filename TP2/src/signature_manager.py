
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from transaction import serialize_transaction
from certificate_manager import CertificateManager


BASE_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = BASE_DIR / "keys"

manager = CertificateManager()


def load_private_key(node):

    key_path = KEYS_DIR / node / f"{node}_ecdsa_private.pem"

    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=None
    )

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Invalid ECDSA private key")

    if not isinstance(private_key.curve, ec.SECP256K1):
        raise ValueError("Expected secp256k1 private key")

    return private_key


def get_verified_public_key(node):

    # Verify certificate using the trusted CA
    certificate = manager.verify_node(node)

    public_key = certificate.public_key()

    return public_key


def sign_transaction(transaction):

    sender = transaction["sender"]

    private_key = load_private_key(sender)

    # Verify sender certificate before signing
    certificate = manager.verify_node(sender)

    certificate_public_key = certificate.public_key()

    # Ensure private key matches the certified public key
    private_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    certificate_bytes = certificate_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if private_bytes != certificate_bytes:
        raise ValueError("Private key does not match certificate")

    signature = private_key.sign(
        serialize_transaction(transaction),
        ec.ECDSA(hashes.SHA256())
    )

    return base64.b64encode(signature).decode("ascii")


def verify_transaction(transaction):

    try:

        sender = transaction["sender"]

        # Obtain trusted public key from CA-verified certificate
        public_key = get_verified_public_key(sender)

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False

        if not isinstance(public_key.curve, ec.SECP256K1):
            return False

        signature = base64.b64decode(
            transaction["signature"],
            validate=True
        )

        unsigned_transaction = {
            key: value
            for key, value in transaction.items()
            if key != "signature"
        }

        public_key.verify(
            signature,
            serialize_transaction(unsigned_transaction),
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except Exception as error:

        print(f"[VERIFY FAILED] {error}")
        return False
