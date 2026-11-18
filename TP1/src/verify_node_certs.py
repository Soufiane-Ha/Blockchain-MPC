from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
CERTS = ROOT / "certificates"

NODES = ["Alice", "Bob", "Carol", "Dave"]

ca_cert = x509.load_pem_x509_certificate(
    (CERTS / "ca_certificate.pem").read_bytes()
)

ca_key = serialization.load_pem_private_key(
    (KEYS / "ca_private_key.pem").read_bytes(),
    password=None,
)

now = datetime.now(timezone.utc)


def utc_time(value):
    # Compatible with multiple cryptography versions.
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def verify_rsa_signature(certificate, public_key):
    public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )


# Verify that the CA certificate is self-signed correctly.
if ca_cert.subject != ca_cert.issuer:
    raise SystemExit("ERROR: CA subject and issuer do not match.")

verify_rsa_signature(ca_cert, ca_cert.public_key())

if not isinstance(ca_key, rsa.RSAPrivateKey):
    raise SystemExit("ERROR: The CA private key is not RSA.")

if (
    ca_key.public_key().public_numbers()
    != ca_cert.public_key().public_numbers()
):
    raise SystemExit("ERROR: CA private key does not match its certificate.")

print("OK: CA certificate and private key verified.")

for node in NODES:
    cert_path = CERTS / f"{node.lower()}_certificate.pem"
    key_path = KEYS / f"{node.lower()}_private_key.pem"

    if not cert_path.exists() or not key_path.exists():
        raise SystemExit(f"ERROR: Missing certificate or key for {node}.")

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=None,
    )

    if cert.issuer != ca_cert.subject:
        raise SystemExit(f"ERROR: Incorrect issuer for {node}.")

    verify_rsa_signature(cert, ca_cert.public_key())

    common_names = cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME
    )
    if not common_names or common_names[0].value != node:
        raise SystemExit(f"ERROR: Incorrect subject for {node}.")

    constraints = cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value
    if constraints.ca:
        raise SystemExit(f"ERROR: {node} must not be a CA.")

    if not (
        utc_time(cert.not_valid_before)
        <= now
        <= utc_time(cert.not_valid_after)
    ):
        raise SystemExit(f"ERROR: Certificate for {node} is expired or not yet valid.")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise SystemExit(f"ERROR: Private key for {node} is not RSA.")

    if (
        private_key.public_key().public_numbers()
        != cert.public_key().public_numbers()
    ):
        raise SystemExit(f"ERROR: Private key does not match {node}'s certificate.")

    print(f"OK: {node} certificate, signature, validity and key match.")

print("\nSUCCESS: All four node certificates passed verification.")
