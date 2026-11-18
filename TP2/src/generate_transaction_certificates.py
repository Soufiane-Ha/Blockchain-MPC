
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# Project paths
BASE = Path(__file__).resolve().parent.parent

OLD_CERTS = BASE.parent / "TP1" / "certificates"
OLD_KEYS = BASE.parent / "TP1" / "keys"

CERT_DIR = BASE / "certificates"
KEY_DIR = BASE / "keys"

NODES = ["alice", "bob", "carol", "dave"]

def main():

    # Load existing CA certificate
    ca_cert = x509.load_pem_x509_certificate(
        (OLD_CERTS / "ca_certificate.pem").read_bytes()
    )

    # Load CA private key (used only by this issuance script)
    ca_key = serialization.load_pem_private_key(
        (OLD_KEYS / "ca_private_key.pem").read_bytes(),
        password=None
    )

    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA CA private key")

    # Verify that CA certificate and private key match
    ca_public = ca_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    key_public = ca_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if ca_public != key_public:
        raise ValueError("CA private key does not match CA certificate")

    for node in NODES:

        print(f"\nGenerating certificate for {node.upper()}")

        # Generate ECDSA secp256k1 key
        private_key = ec.generate_private_key(
            ec.SECP256K1()
        )

        # Use the existing node identity
        old_cert = x509.load_pem_x509_certificate(
            (OLD_CERTS / f"{node}_certificate.pem").read_bytes()
        )

        subject = old_cert.subject

        # Create a new certificate
        now = datetime.now(timezone.utc)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(
                    ca=False,
                    path_length=None
                ),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(
                        f"urn:blockchain-mpc:node:{node}"
                    )
                ]),
                critical=False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    private_key.public_key()
                ),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_cert.public_key()
                ),
                critical=False
            )
            .sign(
                private_key=ca_key,
                algorithm=hashes.SHA256()
            )
        )

        # Save transaction private key
        key_path = KEY_DIR /  NODES/ f"{node}_tx_private_key.pem"

        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        # Save transaction certificate
        cert_path = CERT_DIR / f"{node}_tx_certificate.pem"

        cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )

        print("Curve:", private_key.curve.name)
        print("Certificate:", cert_path.name)
        print("Private key:", key_path.name)
        print("Issuer:", cert.issuer.rfc4514_string())
        print("Status: CREATED")

    print("\nAll transaction certificates generated.")

if __name__ == "__main__":
    main()
